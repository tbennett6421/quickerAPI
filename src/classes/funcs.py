import hashlib

def md5(p):
    return hashlib.md5(p.encode()).hexdigest()

def sha1(p):
    return hashlib.sha1(p.encode()).hexdigest()

def sha256(p):
    return hashlib.sha256(p.encode()).hexdigest()
