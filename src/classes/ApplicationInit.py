import pandas as pd
from pyasn import pyasn
from whois import whois
from ipwhois import IPWhois

from src.classes.ThreatMiner import ThreatMiner
from src.classes.BuildingBlocks import State as SharedEngine
from src.classes.freq import FreqCounter
from src.classes.utils import log_health,load_alexa,load_cisco,isIPAddress

def init_pandas():
    pd.set_option('display.max_rows', 5)
    pd.set_option('display.max_columns', 5)
    pd.set_option('display.width', 1000)
    pd.set_option('display.colheader_justify', 'center')
    pd.set_option('display.precision', 3)

def init_freq(app):
    app.se.freq = lambda: None
    app.se.freq.default = lambda: None
    app.se.freq.domain = lambda: None
    app.se.freq.default.fc = FreqCounter()
    app.se.freq.domain.fc = FreqCounter()
    try:
        app.se.freq.default.fc.load('resources/freqtable2018.freq')
    except (FileNotFoundError,OSError,NameError) as e:
        app.se.freq.default = None
    try:
        app.se.freq.domain.fc.load('resources/domain.freq')
    except (FileNotFoundError,OSError,NameError) as e:
        app.se.freq.domain = None

def init_alexa(app):
    try:
        app.se.alexa = load_alexa('resources/top-1m-alexa.csv')
    except (FileNotFoundError,OSError,NameError) as e:
        app.se.alexa = None

def init_cisco(app):
    try:
        app.se.cisco = load_cisco('resources/top-1m-cisco.csv')
    except (FileNotFoundError,OSError,NameError) as e:
        app.se.cisco = None

def init_pyasn(app):
    try:
        app.se.asn = pyasn('resources/ipasn.dat')
    except (FileNotFoundError,OSError,NameError) as e:
        app.se.asn = None

def init_whois_dns(app):
    try:
        app.dns_whois = whois
    except (OSError,NameError) as e:
        app.dns_whois = None
        raise e

def init_whois_ip(app):
    try:
        app.ip_whois = IPWhois
    except (OSError,NameError) as e:
        app.ip_whois = None
        raise e

def init(app):
    # Configure pandas display
    init_pandas()

    # Create a SharedEngine()
    app.se = SharedEngine()

    # Load lookup services
    init_alexa(app)
    init_cisco(app)
    init_freq(app)
    init_pyasn(app)
    init_whois_dns(app)
    init_whois_ip(app)

    # Instantiate api services
    app.threatminer = ThreatMiner()

    # finished loading; dump services to stdout
    app.health = log_health(app)
