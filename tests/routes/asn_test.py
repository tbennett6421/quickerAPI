from fastapi.testclient import TestClient
from src.main import app

with TestClient(app) as client:

    def test_read_asn():
        criteria = "8.8.8.8"
        response = client.get(f"/asn/{criteria}")
        assert response.status_code == 200
