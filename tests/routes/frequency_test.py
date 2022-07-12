from fastapi.testclient import TestClient
from src.main import app

with TestClient(app) as client:

    def test_read_freq():
        criteria = "tigershell"

        response = client.get(f"/frequency/{criteria}")
        assert response.status_code == 200

        params = { "table": "default" }
        response = client.get(f"/frequency/{criteria}", params=params)
        assert response.status_code == 200

        params = { "table": "domain" }
        response = client.get(f"/frequency/{criteria}", params=params)
        assert response.status_code == 200
