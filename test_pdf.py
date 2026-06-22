import asyncio
import os
import sys
sys.path.insert(0, os.path.abspath('.'))

from app.utils.report_engine import ComplianceReportGenerator
from motor.motor_asyncio import AsyncIOMotorClient
from app.config.config import get_settings

async def test():
    settings = get_settings()
    db = AsyncIOMotorClient(settings.mongodb_uri)[settings.mongodb_db_name]
    gen = ComplianceReportGenerator('test_tenant', db)
    
    p1 = await gen.generate_monthly_report(2026, 5, 'fbr_pos')
    print('FBR PDF Generated at', p1)
    
    p2 = await gen.generate_monthly_report(2026, 5, 'eto_forensic')
    print('PECA PDF Generated at', p2)

if __name__ == "__main__":
    asyncio.run(test())
