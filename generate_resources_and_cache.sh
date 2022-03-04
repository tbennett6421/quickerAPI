#!/bin/bash

BASE_DIR="resources"

# Download latest cisco umbrella
TARGET_ZIP="${BASE_DIR}/top-1m-cisco.csv.zip"
rm -f "$TARGET_ZIP"
/usr/bin/curl http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip > "$TARGET_ZIP"
/usr/bin/unzip -o "$TARGET_ZIP" -d "$BASE_DIR/"
mv "$BASE_DIR/top-1m.csv" "$BASE_DIR/top-1m-cisco.csv"
rm -f "$TARGET_ZIP"

# Download latest alexa
TARGET_ZIP="${BASE_DIR}/top-1m-alexa.csv.zip"
rm -f "$TARGET_ZIP"
/usr/bin/curl http://s3.amazonaws.com/alexa-static/top-1m.csv.zip > "$TARGET_ZIP"
/usr/bin/unzip -o "$TARGET_ZIP" -d "$BASE_DIR/"
mv "$BASE_DIR/top-1m.csv" "$BASE_DIR/top-1m-alexa.csv"
rm -f "$TARGET_ZIP"

# Fetch asn bgpdata
rm -rf scratch01tmp/
rm -rf rib.*.bz2
python3 -m venv scratch01tmp
source scratch01tmp/bin/activate
pip install pyasn
pyasn_util_download.py --latest
for filename in rib.*.bz2; do mv "$filename" "$BASE_DIR/rib-latest.bz2"; done;
pyasn_util_convert.py --single "$BASE_DIR/rib-latest.bz2" "$BASE_DIR/ipasn.dat"
deactivate
rm -rf "$BASE_DIR/rib-latest.bz2"
rm -rf scratch01tmp/
