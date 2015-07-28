#!/bin/bash
echo "== Generating a private key and using it to sign an x509:"
openssl req -x509 -newkey rsa:2048 -outform DER -out cert.cer -config openssl.conf -set_serial 106
echo ""
echo "== Dumping ASN.1 structure of cert.cer:"
openssl asn1parse -inform DER -in cert.cer -dump -i
echo ""
echo "== Hexdump of cert.cer:"
hexdump -e '"\t" 16/1 "0x%02x, " "\n"' cert.cer
echo ""
echo "== Done"
