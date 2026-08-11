// The fast path: a second gated thread in a process that is already patched must be released
// without being injected again.
//
//   twogates <port>
//
// Two threads connect one after the other. Both must come back patched, and the daemon's log
// must carry exactly one "patched at gate" line for this pid -- the second gate takes the
// release path, which is one signal and no Mach work at all.
//
// The threads are deliberately serialised. Latching is per thread rather than per process
// precisely so that a second thread connecting while the first is still being rescued is also
// gated, but that is a different property from this one and testing them together would not
// tell which had failed.

#include "gatetest.h"

#include <pthread.h>

static int g_port;

static void *connect_once(void *arg) {
    const char *who = (const char *)arg;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    fill_loopback(&a, g_port);
    printf("%s before  patched=%d\n", who, patched());
    fflush(stdout);
    errno = 0;
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("%s after   connect=%d errno=%d (%s) patched=%d\n",
           who, r, errno, r ? strerror(errno) : "ok", patched());
    fflush(stdout);
    close(s);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    g_port = atoi(argv[1]);
    pthread_t t;
    pthread_create(&t, NULL, connect_once, (void *)"one");
    pthread_join(t, NULL);
    pthread_create(&t, NULL, connect_once, (void *)"two");
    pthread_join(t, NULL);
    return 0;
}
