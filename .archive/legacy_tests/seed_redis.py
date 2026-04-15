import os
from redis import Redis


def main():
    url = os.environ.get('REDIS_URL','redis://:W4rS0c_R3d1s_S3cur3_v3_9k8R4tMz5lW2nX@127.0.0.1:6379')
    r = Redis.from_url(url, decode_responses=True)
    try:
        print('PING ->', r.ping())
        r.set('tenant_plan:perf-tenant','Enterprise')
        print('SET OK')
    except Exception as e:
        print('ERROR seeding redis:', e)


if __name__ == '__main__':
    main()
