from fastapi.testclient import TestClient
from src.main import app
from src.classes.funcs import md5,sha1,sha256

with TestClient(app) as client:

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
