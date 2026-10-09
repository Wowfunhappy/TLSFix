// Exercise 10.6/10.7's independent protocol-enable flags with the 10.8
// min/max entry points absent. Mavericks' legacy setters use a range internally,
// so its native context cannot reproduce all old configurations (such as holes).
#include "../src/aquatransport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int tf_debug(void) { return 0; }
static void tf_log(const char *format, ...) { (void)format; }
static unsigned legacy_enabled;
static OSStatus legacy_get_enabled(SSLContextRef c, SSLProtocol p, Boolean *enabled) {
    (void)c;
    if (p != kSSLProtocol2 && p != kSSLProtocol3 && p != kTLSProtocol1)
        return errSecParam;
    *enabled = (legacy_enabled & (1u << p)) != 0;
    return noErr;
}
#define SSLGetProtocolVersionEnabled legacy_get_enabled
#include "../src/mac/aquatransport_reporting.inc"
#undef SSLGetProtocolVersionEnabled
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void) {
    Shadow s; memset(&s, 0, sizeof s);
    CHECK(SSLNewContext(false, &s.ctx) == noErr);
    SSLCipherSuite cipher = 0x002f;
    CHECK(SSLSetEnabledCiphers(s.ctx, &cipher, 1) == noErr);
    // SSL3 + TLS1, the old native defaults. The min/max pointers stay NULL.
    legacy_enabled = (1u << kSSLProtocol3) | (1u << kTLSProtocol1);
    capture_reporting(&s);
    CHECK(s.reportedProtocolStatus == noErr && s.reportedProtocol == kTLSProtocol1);
    CHECK(s.reportedCipherStatus == noErr && s.reportedCipher == cipher);
    legacy_enabled = 1u << kSSLProtocol3;
    capture_reporting(&s);
    CHECK(s.reportedProtocolStatus == noErr && s.reportedProtocol == kSSLProtocol3);
    legacy_enabled = 0;
    capture_reporting(&s);
    CHECK(s.reportedProtocolStatus != noErr && s.reportedProtocol == kSSLProtocolUnknown);
    CHECK(s.reportedCipherStatus != noErr && s.reportedCipher == 0);
    legacy_enabled = (1u << kSSLProtocol2) | (1u << kTLSProtocol1);
    capture_reporting(&s);
    CHECK(s.reportedProtocolStatus == noErr && s.reportedProtocol == kTLSProtocol1);
    legacy_enabled = 1u << kSSLProtocol2;
    cipher = 0x0004;
    CHECK(SSLSetEnabledCiphers(s.ctx, &cipher, 1) == noErr);
    capture_reporting(&s);
    CHECK(s.reportedProtocolStatus == noErr && s.reportedProtocol == kSSLProtocol2);
    CHECK(s.reportedCipherStatus == noErr && s.reportedCipher == cipher);
    CHECK(!reporting_cipher_fits(0x002f, kSSLProtocol2));
    CHECK(!reporting_cipher_fits(0x0005, kSSLProtocol2));
    CHECK(!reporting_cipher_fits(0x00ff, kTLSProtocol1));
    CHECK(!reporting_cipher_fits(0xc027, kTLSProtocol1));
    CHECK(reporting_cipher_fits(0xc027, (SSLProtocol)8));
    cipher = 0xc027;
    if (SSLSetEnabledCiphers(s.ctx, &cipher, 1) == noErr) {
        legacy_enabled = 1u << kTLSProtocol1;
        capture_reporting(&s);
        CHECK(s.reportedProtocolStatus == noErr);
        CHECK(s.reportedCipherStatus != noErr && s.reportedCipher == 0);
    }
    SSLDisposeContext(s.ctx);
    puts("PASS simulated legacy enables without min/max APIs, disabled protocols, cipher version checks");
    return 0;
}
