#!/bin/bash
# Build a private CA, issue a leaf whose CRL distribution point is a local HTTP URL, revoke
# it, and publish the CRL. Nothing touches the system trust store: the test evaluates with
# SecTrustSetAnchorCertificates, so the CA is trusted only inside the test process.
set -e
cd "$(dirname "$0")"
rm -rf work && mkdir -p work/newcerts && cd work
touch index.txt
echo 01 > serial
echo 01 > crlnumber

cat > ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir              = .
database         = index.txt
new_certs_dir    = newcerts
certificate      = ca.crt
serial           = serial
crlnumber        = crlnumber
private_key      = ca.key
default_md       = sha1
default_days     = 3650
default_crl_days = 30
policy           = policy_any
unique_subject   = no
[ policy_any ]
commonName             = supplied
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
emailAddress           = optional
[ req ]
distinguished_name = dn
prompt             = no
[ dn ]
CN = AquaTransport CRL Test CA
[ ca_ext ]
basicConstraints = critical,CA:TRUE
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ leaf_ext ]
basicConstraints      = CA:FALSE
keyUsage              = digitalSignature,keyEncipherment
extendedKeyUsage      = serverAuth
subjectAltName        = DNS:crltest.local
subjectKeyIdentifier  = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://127.0.0.1:8099/test.crl
EOF

cat > leaf.cnf <<'EOF'
[ req ]
distinguished_name = dn
prompt             = no
[ dn ]
CN = crltest.local
EOF

echo "== CA"
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 \
  -nodes -config ca.cnf -extensions ca_ext >/dev/null 2>&1

echo "== leaf (good + revoked, same CA)"
for n in good revoked; do
  openssl req -newkey rsa:2048 -keyout $n.key -out $n.csr -nodes -config leaf.cnf >/dev/null 2>&1
  openssl ca -batch -config ca.cnf -extensions leaf_ext -in $n.csr -out $n.crt >/dev/null 2>&1
done

echo "== revoke one of them"
openssl ca -batch -config ca.cnf -revoke revoked.crt >/dev/null 2>&1

echo "== publish CRL"
openssl ca -batch -config ca.cnf -gencrl -out test.crl.pem >/dev/null 2>&1
openssl crl -in test.crl.pem -outform DER -out test.crl

openssl x509 -in ca.crt      -outform DER -out ca.der
openssl x509 -in good.crt    -outform DER -out good.der
openssl x509 -in revoked.crt -outform DER -out revoked.der

echo "--- CRL contents:"
openssl crl -in test.crl -inform DER -noout -text | grep -A2 "Serial Number" | head -6
echo "--- revoked leaf serial:"
openssl x509 -in revoked.crt -noout -serial
echo "--- good leaf serial:"
openssl x509 -in good.crt -noout -serial
