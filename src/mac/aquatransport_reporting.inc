// The native context remains the authority for what the application expects:
// all protocol/cipher setters still go to Security, including the legacy APIs.
// Read its effective configuration once per handshake, without applying it to
// OpenSSL. In particular, a TLS-1.0-only caller still gets modern TLS on the wire.
//
// Min/max getters arrived in 10.8. Resolve them dynamically; on 10.6/10.7 use
// the per-version enables, which also represent noncontiguous enabled sets.
static OSStatus (*native_protocol_min)(SSLContextRef, SSLProtocol *);
static OSStatus (*native_protocol_max)(SSLContextRef, SSLProtocol *);

static OSStatus reporting_protocol(SSLContextRef c, SSLProtocol *protocol) {
    *protocol = kSSLProtocolUnknown;
    if (native_protocol_min && native_protocol_max) {
        SSLProtocol lo, hi;
        OSStatus r = native_protocol_min(c, &lo);
        if (r != noErr) return r;
        r = native_protocol_max(c, &hi);
        if (r != noErr) return r;
        if (lo > hi || (hi != kSSLProtocol3 && hi != kTLSProtocol1 &&
                        hi != (SSLProtocol)7 && hi != (SSLProtocol)8))
            return errSSLNegotiation;
        *protocol = hi;
        return noErr;
    }
    const SSLProtocol versions[] = { kTLSProtocol1, kSSLProtocol3, kSSLProtocol2 };
    for (size_t i = 0; i < sizeof versions / sizeof versions[0]; ++i) {
        Boolean enabled = false;
        OSStatus r = SSLGetProtocolVersionEnabled(c, versions[i], &enabled);
        if (r != noErr) return r;
        if (enabled) { *protocol = versions[i]; return noErr; }
    }
    return errSSLNegotiation;
}

// Cipher families exposed by Security on 10.6-10.9 (CipherSuite.h). Do not use
// OpenSSL's enabled cipher list here: it omits several suites old callers know.
static int reporting_cipher_fits(SSLCipherSuite cipher, SSLProtocol protocol) {
    if (!cipher || cipher == 0x00ff || cipher == 0xffff) return 0;
    if (protocol == kSSLProtocol2)
        return cipher == 0x0003 || cipher == 0x0004 || cipher == 0x0006 ||
               (cipher >= 0xff80 && cipher <= 0xff83);
    if (cipher >= 0xff00) return 0;
    // SHA-256 CBC and GCM suites introduced for TLS 1.2.
    if ((cipher >= 0x003b && cipher <= 0x0040) ||
        (cipher >= 0x0067 && cipher <= 0x006d) ||
        (cipher >= 0x009c && cipher <= 0x00ad) ||
        (cipher >= 0xc023 && cipher <= 0xc032))
        return protocol == (SSLProtocol)8;
    // ECC and PSK suites require TLS. Classic RSA/DH suites, including AES,
    // are also usable by the native SSL 3 implementation.
    if (cipher >= 0xc000 || (cipher >= 0x002c && cipher <= 0x002e) ||
        (cipher >= 0x008a && cipher <= 0x00b9))
        return protocol >= kTLSProtocol1;
    return 1;
}

static OSStatus reporting_cipher(SSLContextRef c, SSLProtocol protocol,
                                 SSLCipherSuite *cipher) {
    *cipher = 0;
    size_t count = 0;
    OSStatus r = SSLGetNumberEnabledCiphers(c, &count);
    if (r != noErr) return r;
    if (!count) return errSSLNegotiation;
    if (count > (size_t)-1 / sizeof(SSLCipherSuite)) return errSecAllocate;
    SSLCipherSuite *enabled = malloc(count * sizeof *enabled);
    if (!enabled) return errSecAllocate;
    r = SSLGetEnabledCiphers(c, enabled, &count);
    if (r == noErr) {
        r = errSSLNegotiation;
        for (size_t i = 0; i < count; ++i) {
            if (reporting_cipher_fits(enabled[i], protocol)) {
                *cipher = enabled[i]; r = noErr; break;
            }
        }
    }
    free(enabled);
    return r;
}

static void capture_reporting(Shadow *s) {
    s->reportedProtocolStatus = reporting_protocol(s->ctx, &s->reportedProtocol);
    s->reportedCipher = 0;
    s->reportedCipherStatus = s->reportedProtocolStatus;
    if (s->reportedProtocolStatus == noErr)
        s->reportedCipherStatus = reporting_cipher(s->ctx, s->reportedProtocol,
                                                   &s->reportedCipher);
    if (tf_debug())
        tf_log("compatibility host=%s protocol=%d cipher=0x%04x status=%d/%d",
               s->host, (int)s->reportedProtocol, (unsigned)s->reportedCipher,
               (int)s->reportedProtocolStatus, (int)s->reportedCipherStatus);
}
