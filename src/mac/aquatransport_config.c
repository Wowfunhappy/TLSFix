#include "aquatransport_config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <mach-o/dyld.h>

// Config lives under /usr/share because sandboxed targets read these files themselves.
// /System/Library/Sandbox/Profiles/system.sb, which every sandboxed process imports, grants
// file-read* only for world-readable files under /System, /usr/lib, /usr/share,
// /private/var/db/dyld and /Library/Filesystems/NetFSPlugins:
//
//   (allow file-read*
//          (require-all (file-mode #o0004)
//                       (require-any ... (subpath "/usr/share") ...)))
//
// A deny-default daemon such as WebKit's webpushd reads nothing outside that set, so the rule
// files sit inside it to apply everywhere. The installers keep them 0644 to satisfy the
// file-mode clause.
#define TF_DEFAULT_DIR "/usr/share/aquatransport"

static int stat_mtime(const char *name, time_t *t);

const char *tf_dir(void) {
    static const char *d = NULL;
    if (!d) {
        const char *e = getenv("AQUATRANSPORT_DIR");
        d = (e && *e) ? e : TF_DEFAULT_DIR;
    }
    return d;
}

static void tf_path(const char *name, char *out, size_t n) {
    snprintf(out, n, "%s/%s", tf_dir(), name);
}

// Rule and flag files are re-read whenever their mtime changes, so an edit applies without
// restarting anything. The check is throttled to once a second: unthrottled it costs a stat()
// per request for each of redirects.txt and headers.txt, and a full open/read of flags.txt on
// every connection presenting a client certificate. A second is far below the granularity at
// which anyone edits these files. Callers hold the relevant lock.
static int recheck_due(time_t *last) {
    time_t now = time(NULL);
    if (now == *last) return 0;
    *last = now;
    return 1;
}

// A flag is on when its name appears on its own line in flags.txt (one flag per line),
// alongside headers.txt and redirects.txt. Recognised flags: "debug" and "disabled-mtls".
static pthread_mutex_t gFlagLock = PTHREAD_MUTEX_INITIALIZER;
static char  **gFlagName = NULL;
static int     gNFlag = 0;
static time_t  gFlagMtime = 0, gFlagCheck = 0;
static int     gFlagLoaded = 0;

int tf_flag(const char *name) {
    if (!name || !*name) return 0;
    pthread_mutex_lock(&gFlagLock);
    if (!gFlagLoaded || recheck_due(&gFlagCheck)) {
        time_t m = 0;
        int present = stat_mtime("flags.txt", &m);
        if (!gFlagLoaded || (present && m != gFlagMtime) || (!present && gNFlag)) {
            for (int i = 0; i < gNFlag; i++) free(gFlagName[i]);
            free(gFlagName); gFlagName = NULL; gNFlag = 0;
            char p[1024];
            tf_path("flags.txt", p, sizeof p);
            FILE *f = fopen(p, "r");
            if (f) {
                char buf[512];
                while (fgets(buf, sizeof buf, f)) {
                    size_t l = strlen(buf);
                    while (l && (buf[l-1] == '\n' || buf[l-1] == '\r' || buf[l-1] == ' ' || buf[l-1] == '\t')) buf[--l] = 0;
                    if (!l) continue;
                    char **nn = (char **)realloc(gFlagName, sizeof(char *) * (gNFlag + 1));
                    if (!nn) break;
                    gFlagName = nn;
                    gFlagName[gNFlag] = strdup(buf);
                    if (!gFlagName[gNFlag]) break;
                    gNFlag++;
                }
                fclose(f);
            }
            gFlagMtime = present ? m : 0;
            gFlagLoaded = 1;
        }
    }
    int hit = 0;
    for (int i = 0; i < gNFlag; i++) if (!strcmp(gFlagName[i], name)) { hit = 1; break; }
    pthread_mutex_unlock(&gFlagLock);
    return hit;
}

static pthread_once_t gDbgOnce = PTHREAD_ONCE_INIT;
static int gDbg = 0;
static void dbg_init(void) { gDbg = tf_flag("debug"); }
int tf_debug(void) { pthread_once(&gDbgOnce, dbg_init); return gDbg; }

void tf_log(const char *fmt, ...) {
    if (!tf_debug()) return;
    // Per-uid path: a single shared file gets created root-owned 0644 by the first daemon
    // that logs, after which no user process can append to it (and the user cannot even
    // delete it).
    char path[256];
    snprintf(path, sizeof path, "/tmp/aquatransport-%u.log", (unsigned)getuid());
    FILE *f = fopen(path, "a");
    if (!f) return;
    struct timeval tv; gettimeofday(&tv, NULL);
    fprintf(f, "%ld.%03d [%d %s] ", (long)tv.tv_sec, (int)(tv.tv_usec / 1000),
            (int)getpid(), getprogname() ? getprogname() : "?");
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// '*' deliberately does not match '/'. Without that restriction it backtracks across the
// whole URL, so "https://*.apple.com/" also matches
// "https://tracker.example/?u=https://cdn.apple.com/x" -- the star eats the real host and
// a rule meant for one site fires on another. Confining it to a single path segment keeps
// multi-label subdomains working ("*" covers "en.m" in "en.m.wikipedia.org") while a star
// can never escape the component it sits in.
//
// On success *consumed, when given, receives how many bytes of s the pattern accounted for.
// Redirects need that: with a wildcard in the pattern the matched length differs from
// strlen(pattern), and the tail past it is what gets spliced onto the replacement.
static int glob_prefix(const char *pattern, const char *s, size_t *consumed) {
    if (!pattern || !s) return 0;
    const char *s0 = s;
    const char *star = NULL, *sp = NULL;
    while (*s) {
        if (*pattern == '*') { star = ++pattern; sp = s; }
        else if (*pattern == *s) { pattern++; s++; }
        else if (star && *sp != '/') { pattern = star; s = ++sp; }
        else return 0;
        if (!*pattern) {                       // pattern exhausted -> prefix matched
            if (consumed) *consumed = (size_t)(s - s0);
            return 1;
        }
    }
    while (*pattern == '*') pattern++;
    if (*pattern) return 0;                    // s ran out with pattern left over
    if (consumed) *consumed = (size_t)(s - s0);
    return 1;
}

int tf_glob_prefix(const char *pattern, const char *s) {
    return glob_prefix(pattern, s, NULL);
}

// ---- scope matching --------------------------------------------------------
//
// Identity is derived from the main executable's path and name only -- no CFBundle, no
// Info.plist parsing, nothing that could misbehave in an unusual process. For
// /Applications/Dictionary.app/Contents/MacOS/Dictionary that yields bundle name
// "Dictionary" and executable name "Dictionary".
//
// Note this identifies the process making the request, which is not always the app the
// user thinks of: a WebKit2 app hands its loads to the shared com.apple.WebKit.Networking
// service, so a rule scoped to Safari would never match. The apps these rules target
// (Dictionary, HelpViewer, iWork, Twitter) all use WebKit1 and load in-process.

static char gAppName[256];
static char gExeName[256];
static pthread_once_t gIdOnce = PTHREAD_ONCE_INIT;

static void id_init(void) {
    const char *exe = _dyld_get_image_name(0);
    if (exe) {
        const char *slash = strrchr(exe, '/');
        snprintf(gExeName, sizeof gExeName, "%s", slash ? slash + 1 : exe);
        // ".../Foo.app/Contents/MacOS/Foo" -> "Foo"
        const char *app = strstr(exe, ".app/");
        if (app) {
            const char *start = app;
            while (start > exe && *(start - 1) != '/') start--;
            size_t n = (size_t)(app - start);
            if (n && n < sizeof gAppName) { memcpy(gAppName, start, n); gAppName[n] = 0; }
        }
    }
    if (!gExeName[0]) {
        const char *pn = getprogname();
        if (pn) snprintf(gExeName, sizeof gExeName, "%s", pn);
    }
}

// Tokens are separated by commas, not spaces: plenty of executables have a space in the
// name ("QuickTime Player", "App Store"). Whitespace around a token is trimmed, so
// "Pages, Numbers, Keynote" and "Pages,Numbers,Keynote" are the same list, and empty
// tokens are skipped.
int tf_scope_matches(const char *scope) {
    if (!scope || !*scope) return 0;
    pthread_once(&gIdOnce, id_init);
    const char *p = scope;
    while (*p) {
        const char *end = p;
        while (*end && *end != ',') end++;
        const char *tok_end = end;
        while (p < tok_end && (*p == ' ' || *p == '\t')) p++;
        while (tok_end > p && (tok_end[-1] == ' ' || tok_end[-1] == '\t')) tok_end--;
        size_t len = (size_t)(tok_end - p);
        if (len == 1 && *p == '*') return 1;
        // Accept "Foo" and "Foo.app" alike.
        if (len > 4 && !strncmp(tok_end - 4, ".app", 4)) len -= 4;
        if (len && len < 256) {
            char tok[256];
            memcpy(tok, p, len); tok[len] = 0;
            if (gAppName[0] && !strcmp(tok, gAppName)) return 1;
            if (gExeName[0] && !strcmp(tok, gExeName)) return 1;
        }
        p = (*end == ',') ? end + 1 : end;
    }
    return 0;
}

// ---- rule files ------------------------------------------------------------
// Both files are blocks separated by blank lines. In redirects.txt a block is two
// lines (from, to). In headers.txt a block is a URL pattern followed by one or
// more "Name: value" lines.

typedef struct { char **line; int n; } block;

static void block_free(block *b) {
    for (int i = 0; i < b->n; i++) free(b->line[i]);
    free(b->line); b->line = NULL; b->n = 0;
}

// Reads a file into blocks. Returns count, or -1 if the file is absent/unreadable.
static int read_blocks(const char *name, block **out, time_t *mtime) {
    char p[1024]; struct stat st;
    tf_path(name, p, sizeof p);
    if (stat(p, &st) != 0) return -1;
    *mtime = st.st_mtime;
    FILE *f = fopen(p, "r");
    if (!f) return -1;

    block *blocks = NULL; int nb = 0;
    block cur; cur.line = NULL; cur.n = 0;
    char buf[2048];
    while (fgets(buf, sizeof buf, f)) {
        size_t l = strlen(buf);
        while (l && (buf[l-1] == '\n' || buf[l-1] == '\r' || buf[l-1] == ' ' || buf[l-1] == '\t')) buf[--l] = 0;
        if (l == 0) {                                       // blank line ends a block
            if (cur.n) {
                blocks = (block *)realloc(blocks, sizeof(block) * (nb + 1));
                blocks[nb++] = cur; cur.line = NULL; cur.n = 0;
            }
            continue;
        }
        cur.line = (char **)realloc(cur.line, sizeof(char *) * (cur.n + 1));
        cur.line[cur.n++] = strdup(buf);
    }
    if (cur.n) { blocks = (block *)realloc(blocks, sizeof(block) * (nb + 1)); blocks[nb++] = cur; }
    fclose(f);
    *out = blocks;
    return nb;
}

static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static tf_redirect *gRed = NULL; static int gNRed = 0; static time_t gRedMtime = 0; static int gRedLoaded = 0;
static tf_headerrule *gHdr = NULL; static int gNHdr = 0; static time_t gHdrMtime = 0; static int gHdrLoaded = 0;
static time_t gRedCheck = 0, gHdrCheck = 0;

static int stat_mtime(const char *name, time_t *t) {
    char p[1024]; struct stat st;
    tf_path(name, p, sizeof p);
    if (stat(p, &st) != 0) return 0;
    *t = st.st_mtime; return 1;
}

int tf_redirects(const tf_redirect **out) {
    pthread_mutex_lock(&gLock);
    time_t m = 0;
    int present = (!gRedLoaded || recheck_due(&gRedCheck)) ? stat_mtime("redirects.txt", &m) : -1;
    if (present < 0) { /* checked within the last second; use what is loaded */ }
    else if (!gRedLoaded || (present && m != gRedMtime) || (!present && gNRed)) {
        for (int i = 0; i < gNRed; i++) { free(gRed[i].scope); free(gRed[i].from); free(gRed[i].to); }
        free(gRed); gRed = NULL; gNRed = 0;
        block *b = NULL; time_t mt = 0;
        int nb = read_blocks("redirects.txt", &b, &mt);
        if (nb > 0) {
            gRed = (tf_redirect *)calloc(nb, sizeof(tf_redirect));
            for (int i = 0; i < nb; i++) {
                if (b[i].n >= 3) {                       // scope, from, to
                    gRed[gNRed].scope = strdup(b[i].line[0]);
                    gRed[gNRed].from  = strdup(b[i].line[1]);
                    gRed[gNRed].to    = strdup(b[i].line[2]);
                    gNRed++;
                }
                block_free(&b[i]);
            }
            free(b);
        }
        gRedMtime = mt; gRedLoaded = 1;
    }
    *out = gRed;
    int n = gNRed;
    pthread_mutex_unlock(&gLock);
    return n;
}

int tf_headerrules(const tf_headerrule **out) {
    pthread_mutex_lock(&gLock);
    time_t m = 0;
    int present = (!gHdrLoaded || recheck_due(&gHdrCheck)) ? stat_mtime("headers.txt", &m) : -1;
    if (present < 0) { /* checked within the last second; use what is loaded */ }
    else if (!gHdrLoaded || (present && m != gHdrMtime) || (!present && gNHdr)) {
        for (int i = 0; i < gNHdr; i++) {
            free(gHdr[i].scope);
            free(gHdr[i].pattern);
            for (int j = 0; j < gHdr[i].nlines; j++) free(gHdr[i].lines[j]);
            free(gHdr[i].lines);
        }
        free(gHdr); gHdr = NULL; gNHdr = 0;
        block *b = NULL; time_t mt = 0;
        int nb = read_blocks("headers.txt", &b, &mt);
        if (nb > 0) {
            gHdr = (tf_headerrule *)calloc(nb, sizeof(tf_headerrule));
            for (int i = 0; i < nb; i++) {
                if (b[i].n >= 3) {                       // scope, pattern, one or more headers
                    gHdr[gNHdr].scope   = strdup(b[i].line[0]);
                    gHdr[gNHdr].pattern = strdup(b[i].line[1]);
                    gHdr[gNHdr].nlines  = b[i].n - 2;
                    gHdr[gNHdr].lines   = (char **)calloc(b[i].n - 2, sizeof(char *));
                    for (int j = 2; j < b[i].n; j++) gHdr[gNHdr].lines[j-2] = strdup(b[i].line[j]);
                    gNHdr++;
                }
                block_free(&b[i]);
            }
            free(b);
        }
        gHdrMtime = mt; gHdrLoaded = 1;
    }
    *out = gHdr;
    int n = gNHdr;
    pthread_mutex_unlock(&gLock);
    return n;
}

int tf_name_listed(const char *file, const char *name) {
    if (!name || !*name) return 0;
    char p[1024];
    tf_path(file, p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    char buf[512];
    int hit = 0;
    while (fgets(buf, sizeof buf, f)) {
        size_t l = strlen(buf);
        while (l && (buf[l-1] == '\n' || buf[l-1] == '\r' || buf[l-1] == ' ' || buf[l-1] == '\t')) buf[--l] = 0;
        if (l == 0) continue;
        if (!strcmp(buf, name)) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

char *tf_apply_redirect(const char *url) {
    if (!url) return NULL;
    const tf_redirect *r = NULL;
    int n = tf_redirects(&r);
    for (int i = 0; i < n; i++) {
        if (!tf_scope_matches(r[i].scope)) continue;
        size_t fl = 0;
        if (!glob_prefix(r[i].from, url, &fl)) continue;
        const char *tail = url + fl;
        size_t need = strlen(r[i].to) + strlen(tail) + 1;
        char *out = (char *)malloc(need);
        if (!out) return NULL;
        snprintf(out, need, "%s%s", r[i].to, tail);
        return out;
    }
    return NULL;
}
