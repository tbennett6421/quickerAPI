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

