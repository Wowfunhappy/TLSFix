// The inherited-socket gate: fd 0 is already a connected socket, so this process calls neither
// connect nor accept and its first touch of the network is a read. That is the case launchd's
// inetdCompatibility jobs are in, and the only one of the three gates that has to watch a hot
// syscall to see it.

#include "gatetest.h"

int main(void) {
    printf("before  patched=%d\n", patched());
    fflush(stdout);

    char b[64];
    errno = 0;
    int n = (int)read(0, b, sizeof b - 1);
    printf("after   read=%d errno=%d (%s) patched=%d\n",
           n, errno, n < 0 ? strerror(errno) : "ok", patched());
    if (n > 0) { b[n] = 0; printf("payload %s", b); }
    fflush(stdout);
    return 0;
}
