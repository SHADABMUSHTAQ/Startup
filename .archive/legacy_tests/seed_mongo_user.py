import os
from pymongo import MongoClient
from datetime import datetime


def main():
    mongo_uri = os.environ.get('MONGODB_URI', 'mongodb://127.0.0.1:27017/WarSOC_DB')
    db_name = os.environ.get('MONGODB_DB_NAME', 'WarSOC_DB')
    client = MongoClient(mongo_uri)
    db = client[db_name]
    tenant_id = os.environ.get('TEST_TENANT', 'perf-tenant')
    user = {
        'username': f'user_{tenant_id}',
        'email': f'{tenant_id}@example.test',
        'hashed_password': '',
        'tenant_id': tenant_id,
        'plan_type': 'Enterprise',
        'role': 'admin',
        'has_active_plan': True,
        'created_at': datetime.utcnow()
    }
    existing = db['users'].find_one({'tenant_id': tenant_id})
    if existing:
        print('User already exists for', tenant_id)
    else:
        db['users'].insert_one(user)
        print('Inserted test user for', tenant_id)


if __name__ == '__main__':
    main()
