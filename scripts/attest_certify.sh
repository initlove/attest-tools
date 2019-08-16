#
# Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, version 2 of the
# License.
#
# File: attest_certify.sh
#      Script for certifying a TPM key.
#

#! /bin/bash

function usage() {
    echo "Usage: $0 -i <AIK priv> -u <AIK pub> -j <AIK parent handle>\
-k <key priv> -l <key pub> -m <key parent handle>\
-a <tpms_attest> -s <signature>"
    echo "Options:"
    echo -e "\t-h: help"
    echo -e "\t-i <AIK priv>: AIK private portion"
    echo -e "\t-u <AIK pub>: AIK public portion"
    echo -e "\t-j <AIK parent handle>: AIK parent handle"
    echo -e "\t-k <key priv>: key private portion"
    echo -e "\t-l <key pub>: key public portion"
    echo -e "\t-m <key parent handle>: key parent handle"
    echo -e "\t-a <tpms_attest>: marshalled TPMS_ATTEST structure"
    echo -e "\t-s <signature>: marshalled TPMT_SIGNATURE structure"
    echo -e "\t-o <skae>: SKAE extension in DER format"
}

aik_priv=""
aik_pub=""
aik_parent="81000001"
key_priv=""
key_pub=""
key_parent="81000001"
tpms_attest=""
signature=""
skae=""

while getopts "hi:u:j:k:l:m:a:s:o:" opt; do
    case "$opt" in
    h)
        usage
        exit 0
        ;;
    i)  aik_priv=$OPTARG
        ;;
    u)  aik_pub=$OPTARG
        ;;
    j)  aik_parent=$OPTARG
        ;;
    k)  key_priv=$OPTARG
        ;;
    l)  key_pub=$OPTARG
        ;;
    m)  key_parent=$OPTARG
        ;;
    a)  tpms_attest=$OPTARG
        ;;
    s)  signature=$OPTARG
        ;;
    o)  skae=$OPTARG
        ;;
    esac
done

if [ -z "$aik_priv" ] || [ -z "$aik_pub" ] || [ -z "$key_pub" ] || \
   [ -z "$tpms_attest" ] || [ -z "$signature" ]; then
    echo "Missing parameter"
    usage
    exit 1
fi

aik_handle=$(tssload -hp $aik_parent -ipr $aik_priv -ipu $aik_pub)
if [ $? -eq 0 ]; then
    aik_handle=${aik_handle:(-8)}
fi

key_handle=$(tssload -hp $key_parent -ipr $key_priv -ipu $key_pub)
if [ $? -eq 0 ]; then
    key_handle=${key_handle:(-8)}
fi

tsscertify -ho $key_handle -hk $aik_handle -oa $tpms_attest -os $signature

tssflushcontext -ha $aik_handle
tssflushcontext -ha $key_handle

if [ -n "$skae" ]; then
    ../src/attest_create_skae -a $tpms_attest -s $signature -e 2.0 $skae
fi
