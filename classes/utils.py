## Standard Libraries
import ipaddress

## Third Party libraries
import pandas as pd

def isIPAddress(i):
    try:
        _ = ipaddress.ip_address(i)
        return True
    except ValueError:
        return False

def is_none(x):
    if isinstance(x, type(None)):
        return True
    else:
        return False

def is_service_alive(x):
    x = is_none(x)
    if x:
        return False
    else:
        return True

def log_health(app):
    print("===Service Health===")
    print(f"freq::default  => {is_service_alive(app.freq.default)}")
    print(f"freq::domain   => {is_service_alive(app.freq.domain)}")
    print(f"asn            => {is_service_alive(app.asn)}")
    print(f"alexa          => {is_service_alive(app.alexa)}")
    print(f"cisco          => {is_service_alive(app.cisco)}")

def log_exception(e):
    # @todo: implement logging
    print(f"Caught Exception type({type(e)}) => {e}")

def load_1m_list(filename):
    data = pd.read_csv(filename, names=['rank', 'domain'])
    return data

def load_alexa(filename):
    try:
        alexa = load_1m_list(filename)
        return alexa
    except FileNotFoundError as e:
        log_exception(e)
        return None
    except Exception as e:
        log_exception(e)

def load_cisco(filename):
    try:
        cisco = load_1m_list(filename)
        return cisco
    except FileNotFoundError as e:
        log_exception(e)
        return None
    except Exception as e:
        log_exception(e)
