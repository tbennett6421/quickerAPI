__code_color_support__ = True

## Standard Libraries
import ipaddress

## Third Party libraries
import pandas as pd
if __code_color_support__:
    try:
        import colorama
        from termcolor import colored
        # negate args.disable_color; init_colors if needed

    except ImportError:
        __code_color_support__ = False

def return_red_str(msg):
    return colored(msg, 'white', 'on_red')

def return_green_str(msg):
    return colored(msg, 'green')

def init_colors(b=True):
    if b:
        colorama.init()
    else:
        global __code_color_support__
        __code_color_support__ = False

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
    health = {
        'freq.default': is_service_alive(app.freq.default),
        'freq::domain': is_service_alive(app.freq.default),
        'asn':          is_service_alive(app.asn),
        'alexa':        is_service_alive(app.alexa),
        'cisco':        is_service_alive(app.cisco),
        'ip_whois':     is_service_alive(app.ip_whois),
        'dns_whois':    is_service_alive(app.dns_whois),
    }
    print("===Service Health===")
    for k,v in health.items():
        if v:
            fmt = "{:<15} => {: >}".format(k,return_green_str(v))
            print(fmt)
        else:
            fmt = "{:<15} => {: >}".format(k,return_red_str(v))
            print(fmt)
    return health

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

### Mainline
init_colors(__code_color_support__)
