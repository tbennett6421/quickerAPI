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
    def test_read_health():
        response = client.get("/health/")
        assert response.status_code == 200

    def test_read_health_healthy():
        """ Check /health/ and fail if any services are down """
        response = client.get("/health/")
        assert response.status_code == 200
        for _,v in response.json().items():
            if v is False:
                assert False

    def test_read_services():
        response = client.get("/services")
        assert response.status_code == 200
