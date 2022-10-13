#!/bin/sh
source env/bin/activate
python -m pytest -v
deactivate
