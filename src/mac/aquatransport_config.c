#include "aquatransport_config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>

#define TF_DEFAULT_DIR "/Library/AquaTransport"

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

int tf_flag(const char *name) {
    char p[1024]; struct stat st;
    tf_path(name, p, sizeof p);
    return stat(p, &st) == 0;
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
    fprintf(f, "[%d %s] ", (int)getpid(), getprogname() ? getprogname() : "?");
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

int tf_glob_prefix(const char *pattern, const char *s) {
    if (!pattern || !s) return 0;
    const char *star = NULL, *sp = NULL;
    while (*s) {
        if (*pattern == '*') { star = ++pattern; sp = s; }
        else if (*pattern == *s) { pattern++; s++; }
        else if (star) { pattern = star; s = ++sp; }
        else return 0;
        if (!*pattern) return 1;               // pattern exhausted -> prefix matched
    }
    while (*pattern == '*') pattern++;
    return *pattern == 0;
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

int tf_scope_matches(const char *scope) {
    if (!scope || !*scope) return 0;
    pthread_once(&gIdOnce, id_init);
    const char *p = scope;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != ' ' && *end != '\t') end++;
        size_t len = (size_t)(end - p);
        if (len == 1 && *p == '*') return 1;
        // Accept "Foo" and "Foo.app" alike.
        if (len > 4 && !strncmp(end - 4, ".app", 4)) len -= 4;
        if (len && len < 256) {
            char tok[256];
            memcpy(tok, p, len); tok[len] = 0;
            if (gAppName[0] && !strcmp(tok, gAppName)) return 1;
            if (gExeName[0] && !strcmp(tok, gExeName)) return 1;
        }
        p = end;
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
        if (l == 0 || buf[0] == '#') {                      // blank line or comment ends a block
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

static int stat_mtime(const char *name, time_t *t) {
    char p[1024]; struct stat st;
    tf_path(name, p, sizeof p);
    if (stat(p, &st) != 0) return 0;
    *t = st.st_mtime; return 1;
}

int tf_redirects(const tf_redirect **out) {
    pthread_mutex_lock(&gLock);
    time_t m = 0;
    int present = stat_mtime("redirects.txt", &m);
    if (!gRedLoaded || (present && m != gRedMtime) || (!present && gNRed)) {
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
                } else {
                    // Most likely a pre-scope rules file, where a block was just from/to.
                    tf_log("redirects.txt: ignoring %d-line block starting \"%s\" "
                           "(needs a scope line first: \"*\" or app names)",
                           b[i].n, b[i].n ? b[i].line[0] : "");
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
    int present = stat_mtime("headers.txt", &m);
    if (!gHdrLoaded || (present && m != gHdrMtime) || (!present && gNHdr)) {
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
                } else {
                    tf_log("headers.txt: ignoring %d-line block starting \"%s\" "
                           "(needs a scope line first: \"*\" or app names)",
                           b[i].n, b[i].n ? b[i].line[0] : "");
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
        if (l == 0 || buf[0] == '#') continue;
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
        size_t fl = strlen(r[i].from);
        if (strncmp(url, r[i].from, fl) != 0) continue;
        const char *tail = url + fl;
        size_t need = strlen(r[i].to) + strlen(tail) + 1;
        char *out = (char *)malloc(need);
        if (!out) return NULL;
        snprintf(out, need, "%s%s", r[i].to, tail);
        return out;
    }
    return NULL;
}
