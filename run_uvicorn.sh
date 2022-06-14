#!/bin/sh
source env/bin/activate
uvicorn src.main:app --reload
deactivate
