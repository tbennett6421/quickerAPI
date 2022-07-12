from fastapi.testclient import TestClient
from src.main import app

with TestClient(app) as client:

    def test_fetch_alexa():
        criteria = "google.com"
        response = client.get(f"/alexa/{criteria}")
        assert response.status_code == 200
        assert response.json() == {'alexa_score': 1}
