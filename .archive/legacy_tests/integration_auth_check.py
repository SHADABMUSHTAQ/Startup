#!/usr/bin/env python3
import json
import urllib.request
import urllib.error
import http.client
import urllib.parse
import time

BASE = "http://127.0.0.1:8000/api/v1"


def post(path, data, headers=None):
    url = BASE + path
    data_b = json.dumps(data).encode('utf-8')
    hdrs = {'Content-Type': 'application/json'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data_b, headers=hdrs, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8')
            return resp.getcode(), json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {'error': 'http error with unreadable body'}
    except Exception as ex:
        return None, {'error': str(ex)}


def get(path, token=None):
    url = BASE + path
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8')
            return resp.getcode(), json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {'error': 'http error with unreadable body'}
    except Exception as ex:
        return None, {'error': str(ex)}


def cors_options(path, origin="http://127.0.0.1"):
    url = BASE + path
    parsed = urllib.parse.urlparse(url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.request('OPTIONS', parsed.path, headers={
        'Origin': origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'
    })
    resp = conn.getresponse()
    headers = dict(resp.getheaders())
    body = resp.read().decode('utf-8')
    conn.close()
    return resp.status, headers, body


def main():
    username = "copilot_test_user"
    email = "copilot_test_user@example.com"
    password = "TestPass123!"

    print('== Attempting LOGIN ==')
    code, body = post('/auth/login', {"username": username, "password": password})
    print('LOGIN ->', code, body)

    token = None
    if code == 200 and isinstance(body, dict):
        token = body.get('access_token')

    if not token:
        print('User not present or login failed; attempting SIGNUP...')
        code2, body2 = post('/auth/signup', {"full_name": "Copilot Test", "username": username, "email": email, "password": password})
        print('SIGNUP ->', code2, body2)
        if code2 in (200, 201):
            time.sleep(0.5)
            code, body = post('/auth/login', {"username": username, "password": password})
            print('LOGIN-after-signup ->', code, body)
            if code == 200 and isinstance(body, dict):
                token = body.get('access_token')

    if token:
        print('TOKEN length:', len(token))
        code3, body3 = get('/auth/me', token=token)
        print('/auth/me ->', code3, body3)
    else:
        print('No token obtained; auth flow failed.')

    print('\n== CORS preflight test ==')
    status, headers, body = cors_options('/auth/login', origin='http://127.0.0.1')
    print('OPTIONS @ /auth/login ->', status)
    for k in ('access-control-allow-origin','access-control-allow-methods','access-control-allow-headers'):
        if k in headers:
            print(k + ':', headers[k])

    # test from dev origin 5173
    status2, headers2, body2 = cors_options('/auth/login', origin='http://127.0.0.1:5173')
    print('OPTIONS @ /auth/login from 5173 ->', status2)
    for k in ('access-control-allow-origin','access-control-allow-methods','access-control-allow-headers'):
        if k in headers2:
            print(k + ':', headers2[k])


if __name__ == '__main__':
    main()
