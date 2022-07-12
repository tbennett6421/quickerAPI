from fastapi.testclient import TestClient
from src.main import app

with TestClient(app) as client:

    def test_read_root():
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"msg": "Hello World"}

    def test_read_docs():
        response = client.get("/docs")
        assert response.status_code == 200
        response = client.get("/redoc")
        assert response.status_code == 200
        response = client.get("/openapi.json")
        assert response.status_code == 200

    def test_read_whois():
        criteria = "google.com"

        # @to-do: all: default
        response = client.get(f"/whois/{criteria}")
        assert response.status_code == 501

        # test where domain:whois lookup
        params = {
            "artifact_type": "domain",
            "method": "whois"
        }
        response = client.get(f"/whois/{criteria}", params=params)
        assert response.status_code == 200

    def test_read_whois_ip():
        criteria = '8.8.8.8'
        response = client.get(f"/whois/ip/invalid.tld")
        assert response.status_code == 400
        response = client.get(f"/whois/ip/{criteria}",)
        assert response.status_code == 200
