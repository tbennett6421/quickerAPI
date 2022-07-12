# threat-toolbox
A POC/Learning exercise with FastAPI

# Installation
This project uses FastAPI. Dependencies can be installed as followed

```sh
# Recommended installations
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

```sh
# Manual
pip install fastapi
pip install pytest
pip install "uvicorn[standard]"
```

```sh
# Other dependencies
pip install colorama
pip install ipwhois
pip install pandas
pip install pyasn
pip install python-whois
pip install requests
pip install ratelimit
pip install termcolor
```

It is highly recommended you run generate_resources_and_cache.sh to pull external resources and generate databases needed for the application's various services
```sh
bash -x generate_resources_and_cache.sh
```

# Running the solution
```sh
# running the solution in development mode
uvicorn main:app --reload
```

## Viewing documentation
* 127.0.0.1:8000/docs
* 127.0.0.1:8000/redocs

# Running unit-tests
```sh
pytest
```
or

```sh
make tests
```

# Supported platforms
The following platforms have been tested. Others may work, feel free to add info if you get it working on other platforms
* Microsoft Windows 10
* Mac OS X Big Sur
* Python 3.9.0+

# Resources
|Item|Description|
|---|---|
| domain.freq | frequency table built using alexa top1m and cisco umbrella top 1m |
