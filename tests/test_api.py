import pytest
from fastapi.testclient import TestClient
import sys
import os

# Ensure the app package is importable from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app

client = TestClient(app)

def test_full_analysis_queue_flow():
    """
    Test: Does the file upload endpoint accept a CSV and return analysis_id?
    """
    test_content = "event_id,message,source_ip,timestamp,user\n4625,Failed login attempt,1.1.1.1,2024-01-01T00:00:00Z,admin"
    
    response = client.post(
        "/api/v1/upload/analyze",
        files={"file": ("test_logs.csv", test_content, "text/csv")}
    )
    
    # 1. Check if API accepted it
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    
    # 2. Verify we got an ID for the Frontend to track
    analysis_id = response.json()["analysis_id"]
    assert analysis_id is not None
    
    print(f"Test Success: Analysis {analysis_id} processed successfully.")
