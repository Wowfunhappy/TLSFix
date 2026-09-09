#ifndef AQUATRANSPORT_GSA_MAIL_H
#define AQUATRANSPORT_GSA_MAIL_H

#include <stddef.h>
#include <string.h>

/* Exact iCloud IMAP/SMTP authorities, including Apple's numbered shards.
 * The input is a length-delimited hostname, never a URL or account identity. */
static inline int aq_mail_host(const char *host, size_t length) {
    if (!host || !length || length > 253 || memchr(host, 0, length)) return 0;
    const char *end = host + length;
    if (*host == 'p' || *host == 'P') {
        const char *digits = ++host;
        while (host < end && *host >= '0' && *host <= '9') host++;
        if (host == digits || host == end || *host++ != '-') return 0;
    }
    size_t n = (size_t)(end - host);
    return (n == 16 && (!strncasecmp(host, "imap.mail.me.com", 16) ||
                        !strncasecmp(host, "smtp.mail.me.com", 16))) ||
           (n == 20 && (!strncasecmp(host, "imap.mail.icloud.com", 20) ||
                        !strncasecmp(host, "smtp.mail.icloud.com", 20)));
}

void tf_gsa_prepare_mail(const char *host, size_t length);

#endif
