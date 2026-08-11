// fork inheritance: a patched process that forks WITHOUT exec must have a patched child.
//
//   forkchild <port>
//
// The parent connects, which gates it and gets it patched, and then forks. The child reports
// its own state without connecting to anything, so what it reports can only have come from the
// address space it inherited. This is why there is no fork gate: a fork without an exec needs
// no injection.

#include "gatetest.h"

#include <sys/wait.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);

    printf("parent before  patched=%d\n", patched());
    fflush(stdout);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    fill_loopback(&a, port);
    connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    printf("parent after   patched=%d\n", patched());
    fflush(stdout);

    pid_t p = fork();
    if (p == 0) {
        printf("child   inherited patched=%d\n", patched());
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return 0;
}
