// Shared configuration for both TLSFix subsystems on macOS.
//
// Files live in /Library/TLSFix (override with TLSFIX_DIR for development).
// headers.txt and redirects.txt keep AquaProxy's exact on-disk format so existing
// rule files carry over unchanged and reverting to the proxy stays a one-line change.
//
// Sentinel flags are empty files whose presence turns something off:
//   disabled          everything
//   disabled-tls      the Secure Transport engine only
//   disabled-rewrite  the URL rewriter only
//
// The kill switch is a file *presence* check rather than removal of the dylib,
// because a missing or unreadable inserted library is fatal to every process launch.

#ifndef TLSFIX_CONFIG_H
#define TLSFIX_CONFIG_H

const char *tf_dir(void);
int         tf_flag(const char *name);

// Diagnostics. No-op unless the "debug" sentinel exists; the flag is read once per
// process so leaving the check in hot paths costs a branch. Appends to /tmp/tlsfix.log.
void tf_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int  tf_debug(void);

// Glob match where '*' is the only metacharacter. fnmatch() is unusable here:
// the rule patterns contain literal '?' characters (".../api.php?action=").
// Matching is anchored at the start and open-ended at the end, so
// "https://*.wikipedia.org/w/api.php?action=" matches any URL with that prefix.
int tf_glob_prefix(const char *pattern, const char *s);

typedef struct { char *from; char *to; } tf_redirect;
typedef struct { char *pattern; char **lines; int nlines; } tf_headerrule;

// Rules are cached and reloaded when a file's mtime changes, so edits take
// effect without restarting anything. Callers must not free the returned arrays.
int tf_redirects(const tf_redirect **out);
int tf_headerrules(const tf_headerrule **out);

// Returns a newly allocated URL with `from` replaced by `to` when `url` starts
// with a redirect rule's `from`, else NULL. Caller frees.
char *tf_apply_redirect(const char *url);

#endif
