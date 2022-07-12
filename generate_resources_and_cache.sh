#!/bin/bash

function init () {
    BASE_DIR="resources"
    mkdir $BASE_DIR 2>/dev/null
}

function cisco () {
    echo "[*] Downloading Cisco"
    # Download latest cisco umbrella
    TARGET_ZIP="${BASE_DIR}/top-1m-cisco.csv.zip"
    rm -f "$TARGET_ZIP"
    /usr/bin/curl http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip > "$TARGET_ZIP"
    /usr/bin/unzip -o "$TARGET_ZIP" -d "$BASE_DIR/"
    mv "$BASE_DIR/top-1m.csv" "$BASE_DIR/top-1m-cisco.csv"
    rm -f "$TARGET_ZIP"
}

function alexa () {
    echo "[*] Downloading Alexa"
    # Download latest alexa
    TARGET_ZIP="${BASE_DIR}/top-1m-alexa.csv.zip"
    rm -f "$TARGET_ZIP"
    /usr/bin/curl http://s3.amazonaws.com/alexa-static/top-1m.csv.zip > "$TARGET_ZIP"
    /usr/bin/unzip -o "$TARGET_ZIP" -d "$BASE_DIR/"
    mv "$BASE_DIR/top-1m.csv" "$BASE_DIR/top-1m-alexa.csv"
    rm -f "$TARGET_ZIP"
}

function asn_bgp () {
    echo "[*] Downloading ASN"
    # Fetch asn bgpdata
    rm -rf scratch01tmp/
    rm -rf rib.*.bz2
    python3 -m venv scratch01tmp
    source scratch01tmp/bin/activate
    pip install pyasn
    pyasn_util_download.py --latest
    for filename in rib.*.bz2; do mv "$filename" "$BASE_DIR/rib-latest.bz2"; done;
    pyasn_util_convert.py --single "$BASE_DIR/rib-latest.bz2" "$BASE_DIR/ipasn.dat"
    pyasn_util_asnames.py > "$BASE_DIR/asnames.json"
    deactivate
    rm -rf "$BASE_DIR/rib-latest.bz2"
    rm -rf scratch01tmp/
}

init
while test $# -gt 0; do
    case "$1" in
        -h|--help)
        echo "-h, --help                show brief help"
        echo "-dla, --download-alexa    ensure alexa has been downloaded"
        echo "-dlc, --download-cisco    ensure cisco has been downloaded"
        echo "-dlb, --download-bgp      ensure cisco has been downloaded"
        echo "-doa, --do-all            run all check"
        exit 1
        ;;

        -doa)
            alexa
            cisco
            asn_bgp
            exit 0
        ;;

        --do-all)
            alexa
            cisco
            asn_bgp
            exit 0
        ;;

        -dla)
            alexa
            shift
        ;;

        --download-alexa)
            alexa
            shift
        ;;

        -dlc)
            cisco
            shift
        ;;

        --download-cisco)
            cisco
            shift
        ;;

        -dlb)
            asn_bgp
            shift
        ;;

        --download-bgp)
            asn_bgp
            shift
        ;;

        *)
            break
        ;;
    esac
done
