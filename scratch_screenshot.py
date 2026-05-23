import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await page.goto('http://localhost:5173/login')
        await page.fill('input[type=text]', 'admin@warsoc.com')
        await page.fill('input[type=password]', 'WarSOC2026!')
        await page.click('button[type=submit]')
        await page.wait_for_timeout(5000)
        await page.screenshot(path='dashboard_screenshot.png')
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
