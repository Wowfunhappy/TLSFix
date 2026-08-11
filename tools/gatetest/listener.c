// A listener for the tests that need connect() to actually succeed, since "the syscall
// completed normally after the hold" is half of what the gate tests assert.
//
//   listener <port>
//
// It accepts and immediately closes, in a loop, until it is killed. It is gated at its own
// accept like anything else, which is expected and is not what any test using it is measuring.

#include "gatetest.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    fill_loopback(&a, atoi(argv[1]));
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    listen(ls, 64);
    printf("listening\n");
    fflush(stdout);
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd >= 0) close(fd);
        else if (errno != EINTR) break;
    }
    return 0;
}
