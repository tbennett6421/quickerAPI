from fastapi.testclient import TestClient
from src.main import app
from src.classes.funcs import md5,sha1,sha256

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
        response = client.get("/openapi.json")
        assert response.status_code == 200

    def test_read_hashes():
        criteria = "Hello"
        hashes = {
            "md5": md5(criteria),
            "sha1": sha1(criteria),
            "sha256": sha256(criteria),
        }
        response = client.get(f"/md5/{criteria}")
        assert response.status_code == 200
        assert response.json() == {"md5": hashes['md5']}
        response = client.get(f"/sha1/{criteria}")
        assert response.status_code == 200
        assert response.json() == {"sha1": hashes['sha1']}
        response = client.get(f"/sha256/{criteria}")
        assert response.status_code == 200
        assert response.json() == {"sha256": hashes['sha256']}
        response = client.get(f"/hashes/{criteria}")
        assert response.status_code == 200
        assert response.json() == hashes

    def test_read_asn():
        criteria = "8.8.8.8"
        response = client.get(f"/asn/{criteria}")
        assert response.status_code == 200

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

    def test_read_alexa():
        criteria = "google.com"
        response = client.get(f"/alexa/{criteria}")
        assert response.status_code == 200

    def test_read_cisco():
        criteria = "google.com"
        response = client.get(f"/cisco/{criteria}")
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
