// exec invalidation: a process that connects, is patched, then execs must be re-gated and
// re-patched on its next connection.
//
//   execchain <port> <next>
//
// The library does not survive an exec, so everything the daemon remembers about a pid has to
// stop applying the moment that pid execs. It does not learn this from an event arriving in
// time -- it learns it from the exec timestamp DTrace puts in the gate record, which simply
// stops matching what was recorded for the previous program. This exercises the same mechanism
// xpcproxy drives on every application and XPC service launch on 10.9.

#include "gatetest.h"

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <port> <next>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);

    printf("first   before  patched=%d\n", patched());
    fflush(stdout);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    fill_loopback(&a, port);
    connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    printf("first   after   patched=%d\n", patched());
    fflush(stdout);

    // Same pid, new address space, no library. Whatever the daemon believed about this pid a
    // moment ago is now wrong.
    char *av[] = { argv[2], argv[1], NULL };
    execv(argv[2], av);
    perror("execv");
    return 1;
}
