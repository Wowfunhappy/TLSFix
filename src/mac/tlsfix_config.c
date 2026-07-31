#include "tlsfix_config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

#define TF_DEFAULT_DIR "/Library/TLSFix"

const char *tf_dir(void) {
    static const char *d = NULL;
    if (!d) {
        const char *e = getenv("TLSFIX_DIR");
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
    FILE *f = fopen("/tmp/tlsfix.log", "a");
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
        for (int i = 0; i < gNRed; i++) { free(gRed[i].from); free(gRed[i].to); }
        free(gRed); gRed = NULL; gNRed = 0;
        block *b = NULL; time_t mt = 0;
        int nb = read_blocks("redirects.txt", &b, &mt);
        if (nb > 0) {
            gRed = (tf_redirect *)calloc(nb, sizeof(tf_redirect));
            for (int i = 0; i < nb; i++) {
                if (b[i].n >= 2) {                       // a block needs both from and to
                    gRed[gNRed].from = strdup(b[i].line[0]);
                    gRed[gNRed].to   = strdup(b[i].line[1]);
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
    int present = stat_mtime("headers.txt", &m);
    if (!gHdrLoaded || (present && m != gHdrMtime) || (!present && gNHdr)) {
        for (int i = 0; i < gNHdr; i++) {
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
                if (b[i].n >= 2) {                       // pattern plus at least one header
                    gHdr[gNHdr].pattern = strdup(b[i].line[0]);
                    gHdr[gNHdr].nlines  = b[i].n - 1;
                    gHdr[gNHdr].lines   = (char **)calloc(b[i].n - 1, sizeof(char *));
                    for (int j = 1; j < b[i].n; j++) gHdr[gNHdr].lines[j-1] = strdup(b[i].line[j]);
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

char *tf_apply_redirect(const char *url) {
    if (!url) return NULL;
    const tf_redirect *r = NULL;
    int n = tf_redirects(&r);
    for (int i = 0; i < n; i++) {
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
