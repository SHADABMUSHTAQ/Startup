import asyncio
from app.config.config import get_settings
from redis.asyncio import Redis

async def main():
    settings = get_settings()
    print('Using Redis URL:', settings.redis_url)
    try:
        r = await Redis.from_url(settings.redis_url, decode_responses=True)
        ok = await r.ping()
        print('redis_ping:', ok)

        # Blacklist test
        await r.setex('warsoc:blacklist:test-jti-smoke', 30, 'revoked')
        exists = await r.exists('warsoc:blacklist:test-jti-smoke')
        print('blacklist_exists:', exists)

        # SOAR whitelist test
        tenant = 'WARSOC_SMOKE'
        ip = '10.254.254.1'
        await r.sadd(f'warsoc:soar_whitelist:{tenant}', ip)
        ismem = await r.sismember(f'warsoc:soar_whitelist:{tenant}', ip)
        print('soar_whitelist_sismember:', ismem)

        await r.delete('warsoc:blacklist:test-jti-smoke')
        await r.srem(f'warsoc:soar_whitelist:{tenant}', ip)
        await r.close()
    except Exception as e:
        print('SMOKE ERROR:', e)

if __name__ == '__main__':
    asyncio.run(main())
