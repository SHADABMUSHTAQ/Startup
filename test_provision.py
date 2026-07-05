import urllib.request
import json
import urllib.error

url = 'http://127.0.0.1:8000/api/v1/admin/provision'
data = json.dumps({
    'company_name': 'Acme Corp',
    'plan_type': 'Enterprise',
    'compliance_packs': ['peca_forensic', 'fbr_pos'],
    'max_agents': 50,
    'admin_email': 'admin3@acme.com',
    'admin_name': 'Acme Admin',
    'admin_password': 'SecurePass123!'
}).encode('utf-8')

req = urllib.request.Request(url, data=data, headers={
    'X-Admin-Key': 'W4rS0c_Adm1n_M4st3r_K3y_2026!X',
    'Content-Type': 'application/json'
})

try:
    res = urllib.request.urlopen(req)
    print(res.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print(f"HTTP Error: {e.code}")
    print(e.read().decode('utf-8'))
except Exception as e:
    print(f"Error: {e}")
