## Standard Libraries
from enum import Enum

class frequency_tables(str, Enum):
    default = "default"
    domain = "domain"

class whois_method(str, Enum):
    default = "default"
    whois = "whois"
    threatminer = "threatminer"

class whois_artifact(str, Enum):
    default = "default"
    ip = "ip"
    domain = "domain"
