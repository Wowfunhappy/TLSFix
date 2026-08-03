// Shared configuration for both AquaTransport subsystems on macOS.
//
// Files live in /Library/AquaTransport (override with AQUATRANSPORT_DIR for development).
//
// flags.txt holds one flag name per line. Recognised flags:
//   debug           log handshakes to /tmp/aquatransport-<uid>.log
//   disabled-mtls   hand client-certificate connections back to the system stack

#ifndef AQUATRANSPORT_CONFIG_H
#define AQUATRANSPORT_CONFIG_H

const char *tf_dir(void);
int         tf_flag(const char *name);   // is <name> a line in flags.txt?

// Diagnostics. tf_debug() is a no-op unless "debug" is in flags.txt; it reads the flag once
// per process, so the check costs a branch in hot paths. tf_log appends to
// /tmp/aquatransport-<uid>.log.
void tf_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int  tf_debug(void);

// Glob match where '*' is the only metacharacter. fnmatch() is unusable here:
// the rule patterns contain literal '?' characters (".../api.php?action=").
// Matching is anchored at the start and open-ended at the end, so
// "https://*.wikipedia.org/w/api.php?action=" matches any URL with that prefix.
// '*' matches any run of characters other than '/', so it spans subdomain labels or a
// single path segment but can never reach past the component it appears in.
// Used for both files: headers.txt patterns and redirects.txt "from" lines.
int tf_glob_prefix(const char *pattern, const char *s);

// Every rule block begins with a scope line: "*" for all processes, or a comma-separated
// list of app bundle names ("Dictionary", "Pages, Numbers, Keynote"). Commas rather than
// spaces because executable names contain spaces ("QuickTime Player"). A trailing ".app"
// is accepted and ignored, and the executable name is matched as well as the bundle name.
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
