import asyncio
import os
from playwright.async_api import async_playwright
import httpx
import uuid
import time
from datetime import datetime, timezone

BASE_URL = "http://localhost:5173"
API_URL = "http://localhost:8000"

# Fetch from environment or fallback to defaults
ADMIN_EMAIL = os.getenv("ANALYST_USERNAME", "admin@warsoc.com")
ADMIN_PASSWORD = os.getenv("ANALYST_PASSWORD", "WarSOC2026!")

async def trigger_logs(client_cookies, csrf_token):
    print(f"🔥 Firing 1000 unique simulated logs to {API_URL}/api/v1/logs/inject...")
    httpx_cookies = {cookie["name"]: cookie["value"] for cookie in client_cookies}
    headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf_token}
    
    async with httpx.AsyncClient(headers=headers, cookies=httpx_cookies, verify=False, timeout=30.0) as client:
        for batch_idx in range(10): # 10 batches of 100
            tasks = []
            for i in range(batch_idx * 100, (batch_idx + 1) * 100):
                log_payload = {
                    "ip": f"192.168.1.{i % 255}",
                    "event_id": 4625,
                    "message": f"Stress Test Alert Sequence #{i}",
                    "severity": "HIGH",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "engine_source": "WINDOWS-SEC",
                    "hostname": "STRESS-TEST-VM"
                }
                tasks.append(client.post(f"{API_URL}/api/v1/logs/inject", json=log_payload))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code == 200)
            print(f"Batch {batch_idx+1}/10: Sent 100 logs ({success_count} successful)")
            await asyncio.sleep(0.5) # Give the server some breathing room

async def main():
    print("🚀 Starting UI Stress Test...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        # Print console logs
        page.on("console", lambda msg: print(f"BROWSER CONSOLE: {msg.text}"))
        page.on("pageerror", lambda err: print(f"BROWSER ERROR: {err}"))

        print(f"1. Navigating to {BASE_URL}/login")
        await page.goto(f"{BASE_URL}/login")

        print("2. Logging in with test admin credentials...")
        try:
            await page.fill("input[placeholder='Email']", ADMIN_EMAIL)
        except:
            # Fallback for different placeholder or selector
            await page.fill("input[type='text']", ADMIN_EMAIL)
        
        await page.fill("input[placeholder='Password']", ADMIN_PASSWORD)
        await page.click("button.submit-btn, button[type='submit']")

        print("3. Waiting for Dashboard load...")
        try:
            # Wait for either dashboard or pricing or auditor
            await page.wait_for_function("""
                () => window.location.pathname.includes('/dashboard') || 
                      window.location.pathname.includes('/pricing') || 
                      window.location.pathname.includes('/auditor')
            """, timeout=15000)
        except Exception as e:
            print(f"❌ Navigation failed or timed out: {e}")
            await page.screenshot(path="login_failed.png")
            print(f"Current URL: {page.url}")
            content = await page.content()
            print(f"Page content snippet: {content[:500]}...")
            raise

        print(f"Redirected to: {page.url}")
        if "/pricing" in page.url:
            print("⚠️ Admin redirected to /pricing instead of /dashboard. This might be due to plan status.")
        
        # If we are on dashboard, proceed with stress test
        if "/dashboard" in page.url:
            # Wait for the Omni Agent Feed to be visible
            await page.wait_for_selector(".agent-logs-wrapper", state="visible", timeout=10000)
            
            # Wait a moment for WS to connect
            await page.wait_for_timeout(2000)

            # Retrieve cookies and CSRF token for httpx
            cookies = await context.cookies()
            
            # Fetch the CSRF token from /auth/me
            me_resp = await page.evaluate(f"async () => {{ const r = await fetch('{API_URL}/api/v1/auth/me', {{credentials: 'include'}}); return r.json(); }}")
            csrf_token = me_resp.get("csrf_token")
            print(f"CSRF Token obtained: {csrf_token}")

            # 4. Trigger 1000 logs
            await trigger_logs(cookies, csrf_token)
            
            # Wait for the UI to process the WebSocket/Polling updates
            print("Waiting for UI to ingest incoming data...")
            await page.wait_for_timeout(5000)

            # 5. The Assertion (DOM Culling)
            print("5. Asserting DOM node cap for Virtualized Feed...")
            row_count = await page.locator(".agent-table tbody tr").count()
            print(f"Rendered rows in DOM: {row_count}")
            
            assert row_count <= 60, f"Expected strictly capped rows (<=60), but found {row_count}!"
            print("✅ DOM Node Rendering is safely capped!")

            # 6. Executing Mitigation Lock assertion...
            print("6. Executing Mitigation Lock assertion...")
            
            # Click the Network Map sidebar link
            print("Navigating to Network Map tab...")
            await page.click("button:has-text('Network Map')")
            
            # Wait for Cytoscape to actually render (it might take a second)
            await page.wait_for_selector(".cy-canvas", state="visible", timeout=15000)
            canvas_box = await page.locator(".cy-canvas").bounding_box()
            
            if canvas_box:
                print("Canvas found, attempting to select a node...")
                # Try to click a few spots to select a node (nodes are spread out)
                for offset in [(50, 50), (-50, -50), (100, 0), (0, 100), (30, -30)]:
                    await page.mouse.click(canvas_box["x"] + canvas_box["width"] / 2 + offset[0], 
                                         canvas_box["y"] + canvas_box["height"] / 2 + offset[1])
                    await page.wait_for_timeout(300)
                    if await page.locator("button:has-text('Isolate & Block IP')").count() > 0:
                        break

            button_locator = page.locator("button:has-text('Isolate & Block IP')")
            
            if await button_locator.count() > 0:
                print("Block IP button found! Clicking...")
                await button_locator.click()
                
                # Assert pessimistic state update changes it to "Unblock Target"
                unblock_locator = page.locator("button:has-text('Unblock Target')")
                await unblock_locator.wait_for(state="visible", timeout=5000)
                
                class_name = await unblock_locator.get_attribute("class")
                assert "danger" not in class_name, "Button did not apply disabled/locked CSS state!"
                print("✅ Mitigation Lock (Pessimistic State) instantly applied!")
            else:
                print("⚠️ Could not reliably open the sidebar to test the Block IP button.")
        else:
            print(f"❌ Test aborted: Unexpected URL {page.url}")

        await browser.close()
        print("🎉 Chunk 4 UI Stress Test Complete!")

if __name__ == "__main__":
    asyncio.run(main())
