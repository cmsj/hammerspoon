#!/bin/bash
openssl req -x509 -newkey rsa:2048 -outform DER -out cert.cer -config openssl.conf -set_serial 106
openssl asn1parse -inform DER -in cert.cer -dump -i
