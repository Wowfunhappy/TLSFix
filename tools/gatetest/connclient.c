// The outbound gate: connect() to a local listener.
//
//   connclient <port>
//
// The port is expected to have something listening on it, but the assertion does not depend on
// the connection succeeding for any reason of its own -- what is being tested is that the
// thread was held at the syscall and released with the library present.

#include "gatetest.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);
    printf("before  patched=%d\n", patched());
    fflush(stdout);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    fill_loopback(&a, port);
    errno = 0;
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    printf("after   connect=%d errno=%d (%s) patched=%d\n",
           r, errno, r ? strerror(errno) : "ok", patched());
    close(s);
    return 0;
}
