// The inbound gate: accept(), which is gated on RETURN so that the descriptor exists and the
// thread is held before it can be used. Gating at entry would instead hold the thread for as
// long as the process sat idle waiting for a connection that had not arrived.
//
//   acceptserver <port>
//
// The read after accept is what proves the connection survived the hold: the peer's bytes have
// to arrive intact on a socket whose owner was frozen between the accept and the read.

#include "gatetest.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    fill_loopback(&a, port);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    listen(ls, 8);

    printf("listening\n");
    printf("before  patched=%d\n", patched());
    fflush(stdout);

    errno = 0;
    int fd = accept(ls, NULL, NULL);
    printf("after   accept=%d errno=%d (%s) patched=%d\n",
           fd, errno, fd < 0 ? strerror(errno) : "ok", patched());
    if (fd >= 0) {
        char b[64];
        int n = (int)read(fd, b, sizeof b - 1);
        if (n > 0) { b[n] = 0; printf("payload %s", b); }
        close(fd);
    }
    fflush(stdout);
    return 0;
}
