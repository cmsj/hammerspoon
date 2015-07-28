#!/bin/bash
echo "== Generating a private key and using it to sign an x509:"
#openssl req -x509 -newkey rsa:2048 -outform DER -out cert.cer -config openssl.conf -set_serial 106
echo ""
echo "== Dumping ASN.1 structure of cert.cer:"
openssl asn1parse -inform DER -in cert.cer -dump -i >cert.cer.asn1
echo ""
echo "== Generating HammerspoonRemoteCertTemplate.h:"
#hexdump -e '"\t" 16/1 "0x%02x, " "\n"' cert.cer
INCLUDE_FILE="HammerspoonRemoteCertTemplate.h"

# Clear out the include file
> ${INCLUDE_FILE}

echo "=== Calculating offsets..."

SERIAL_OFFSET=$(( $(grep INTEGER cert.cer.asn1 | sed -n 2p | sed -e 's/:.*//') + 2 ))
echo "#define kSerialOffset    ${SERIAL_OFFSET}" >>${INCLUDE_FILE}

ISSUEDATE_OFFSET=$(( $(grep UTCTIME cert.cer.asn1 | sed -n 1p | sed -e 's/:.*//') + 2 ))
echo "#define kIssueDateOffset ${ISSUEDATE_OFFSET}" >>${INCLUDE_FILE}

EXPIRYDATE_OFFSET=$(( $(grep UTCTIME cert.cer.asn1 | sed -n 2p | sed -e 's/:.*//') + 2 ))
echo "#define kExpDateOffset   ${EXPIRYDATE_OFFSET}" >>${INCLUDE_FILE}

PUBLICKEY_OFFSET=$(( $(grep "BIT STRING" cert.cer.asn1 | sed -n 1p | sed -e 's/:.*//') + 5 ))
echo "#define kPublicKeyOffset ${PUBLICKEY_OFFSET}" >>${INCLUDE_FILE}

CSR_LENGTH=$(grep "BIT STRING" cert.cer.asn1 | sed -n 2p | sed -e 's/:.*//')
echo "#define kCSRLength     ${CSR_LENGTH}u" >>${INCLUDE_FILE}

echo "" >>${INCLUDE_FILE}

echo "=== Dumping template certificate bytes..."
openssl x509 -C -inform DER -in cert.cer -noout | sed -n '/XXX_certificate/,$p' | sed -e 's/unsigned char XXX_certificate/static uint8_t const kCertTemplate/' >>${INCLUDE_FILE}
echo ""
echo "== Done"
