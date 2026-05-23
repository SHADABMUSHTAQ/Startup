import asyncio
import websockets
import ssl

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    async with websockets.connect('wss://localhost/ws/alerts?ticket=INVALID', ssl=ctx) as ws:
        pass

asyncio.run(main())
