import ipaddress

def isIPAddress(self, i):
    try:
        _ = ipaddress.ip_address(i)
        return True
    except ValueError:
        return False
