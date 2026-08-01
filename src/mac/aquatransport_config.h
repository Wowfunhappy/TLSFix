// Shared configuration for both AquaTransport subsystems on macOS.
//
// Files live in /Library/AquaTransport (override with AQUATRANSPORT_DIR for development).
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

#ifndef AQUATRANSPORT_CONFIG_H
#define AQUATRANSPORT_CONFIG_H

const char *tf_dir(void);
int         tf_flag(const char *name);

// Diagnostics. No-op unless the "debug" sentinel exists; the flag is read once per
// process so leaving the check in hot paths costs a branch. Appends to /tmp/aquatransport.log.
void tf_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int  tf_debug(void);

// Glob match where '*' is the only metacharacter. fnmatch() is unusable here:
// the rule patterns contain literal '?' characters (".../api.php?action=").
// Matching is anchored at the start and open-ended at the end, so
// "https://*.wikipedia.org/w/api.php?action=" matches any URL with that prefix.
int tf_glob_prefix(const char *pattern, const char *s);

// Every rule block begins with a scope line: "*" for all processes, or a space-separated
// list of app bundle names ("Dictionary", "Pages Numbers Keynote"). A trailing ".app" is
// accepted and ignored, and the executable name is matched as well as the bundle name.
typedef struct { char *scope; char *from; char *to; } tf_redirect;
typedef struct { char *scope; char *pattern; char **lines; int nlines; } tf_headerrule;

// Does the current process fall within a rule's scope line?
int tf_scope_matches(const char *scope);

// Rules are cached and reloaded when a file's mtime changes, so edits take
// effect without restarting anything. Callers must not free the returned arrays.
int tf_redirects(const tf_redirect **out);
int tf_headerrules(const tf_headerrule **out);

// Returns a newly allocated URL with `from` replaced by `to` when `url` starts
// with a redirect rule's `from`, else NULL. Caller frees.
char *tf_apply_redirect(const char *url);

// Is `name` listed (one entry per line) in the given config file? Used for the
// user-editable rewriter deny list, so a process that misbehaves can be excluded
// without rebuilding. Missing file means "no".
int tf_name_listed(const char *file, const char *name);

#endif
