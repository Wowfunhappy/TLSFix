#!/bin/bash
# Builds a private CA and two client identities for the client-certificate tests: one with an
# RSA-2048 key and one with an RSA-1024 key.
#
# The small key is the point. Apple still issues 1024-bit device identities -- apsd's push
# certificate is one -- and OpenSSL's default security level judges the certificate the client
# *sends* by the same bar it judges the peer's, which silently drops it and sends an empty
# Certificate message instead. The 2048-bit identity is the control: same CA, same server,
# same code path, and it was never affected.
#
# Nothing here touches the system trust store or any keychain. The server trusts this CA
# because it is handed the file; the client accepts the server because mtlsprobe sets
# kSSLSessionOptionBreakOnServerAuth and judges nothing.
set -e
cd "$(dirname "$0")"
rm -rf work && mkdir -p work && cd work

SSL=/usr/bin/openssl
SUBJ_CA="/CN=AquaTransport Test CA"

# sha256 throughout: the engine's peer-side checks stay at the default security level, and a
# sha1-signed CA would fail them for a reason that has nothing to do with what is under test.
$SSL req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "$SUBJ_CA" -keyout ca.key -out ca.crt 2>/dev/null

# CN=localhost so the name matches what mtlsprobe passes to SSLSetPeerDomainName.
$SSL req -newkey rsa:2048 -sha256 -nodes \
    -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
$SSL x509 -req -in server.csr -CA ca.crt -CAkey ca.key -set_serial 2 \
    -days 3650 -sha256 -out server.crt 2>/dev/null

# bits=1024 is the case that broke iMessage; bits=2048 is the control.
for bits in 1024 2048; do
    $SSL req -newkey "rsa:$bits" -sha256 -nodes \
        -subj "/CN=client-rsa$bits" -keyout "client$bits.key" -out "client$bits.csr" 2>/dev/null
    $SSL x509 -req -in "client$bits.csr" -CA ca.crt -CAkey ca.key -set_serial "1$bits" \
        -days 3650 -sha256 -out "client$bits.crt" 2>/dev/null
    $SSL pkcs12 -export -inkey "client$bits.key" -in "client$bits.crt" -certfile ca.crt \
        -passout pass:test123 -out "client$bits.p12" 2>/dev/null
done

echo "made: $(pwd)"
