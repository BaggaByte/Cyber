import sys
sys.path.insert(0, "./src")

import asyncio
from main import launch_scan, ScanRequest
from core.database import SessionLocal
from fastapi import BackgroundTasks

async def test():
    db = SessionLocal()
    req = ScanRequest(target="http://demo.testfire.net/")
    bt = BackgroundTasks()
    try:
        res = await launch_scan(req, bt, db, "")
        print("SUCCESS:", res)
    except Exception as e:
        import traceback
        traceback.print_exc()

asyncio.run(test())
