from fastapi.testclient import TestClient
from .main import app

client = TestClient(app)
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
