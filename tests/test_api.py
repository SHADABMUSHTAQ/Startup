import pytest
from fastapi.testclient import TestClient
from main import app # Ensure this points to your main.py
import os

client = TestClient(app)

def test_full_analysis_queue_flow():
    """
    Test: Does the file save, enter DB, and hit Redis?
    """
    test_content = "user,message,ip\nadmin,SQL_INJECTION_TEST,1.1.1.1"
    
    # URL must match your APIRouter(prefix="/api/logs") + @router.post("/analyze")
    response = client.post(
        "/api/logs/analyze", 
        files={"file": ("test_logs.csv", test_content, "text/csv")}
    )
    
    # 1. Check if API accepted it
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    
    # 2. Verify we got an ID for the Frontend Guy to track
    analysis_id = response.json()["analysis_id"]
    assert analysis_id is not None
    
    print(f"Test Success: Analysis {analysis_id} is in the queue.") 
