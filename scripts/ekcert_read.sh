#! /bin/bash

function usage() {
    echo "Usage: $0 [ -a <EK algo> ] -o <EK cert>"
    echo "Options:"
    echo -e "\t-h: help"
    echo -e "\t-a <EK algo>: algorithm of the EK"
    echo -e "\t-o <EK cert>: EK certificate"
}

ek_algo=sha256

while getopts "ha:o:" opt; do
    case "$opt" in
    h)
        usage
        exit 0
        ;;
    a)  ek_algo=$OPTARG
        ;;
    o)
        ek_cert=$OPTARG
        ;;
    esac
done

if [ -z "$ek_cert" ]; then
    echo "Missing parameter"
    usage
    exit 1
fi

if [ $ek_algo = "sha256" ]; then
    ek_index="0x01c00002"
elif [ $ek_algo = "ec" ]; then
    ek_index="0x01c0000a"
else
    echo "Unknown algorithm $ek_algo"
    exit 1
fi

ek_cert_size=$(tssnvreadpublic -ha $ek_index | \
               awk '$2 == "data" && $3 == "size" { print $4 }')

tssnvread -ha $ek_index -sz $ek_cert_size -of $ek_cert &> /dev/null
