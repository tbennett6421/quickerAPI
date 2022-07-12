from fastapi.testclient import TestClient
from src.main import app

with TestClient(app) as client:

    def test_fetch_cisco():
        criteria = "google.com"
        response = client.get(f"/cisco/{criteria}")
        assert response.status_code == 200
        assert response.json() == {'cisco_score': 1}
