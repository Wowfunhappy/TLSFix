// A process whose progress is externally visible, so "frozen" and "released" can be observed
// without instrumenting it. Used by the recovery and kill-safety tests.
//
//   heartbeat [port]
//
// With a port it connects once first, which is what puts it through the gate; without one it
// simply beats. Either way it prints a line every 300 ms, so a hold shows up as a gap and a
// release shows up as the beats resuming.

#include "gatetest.h"

int main(int argc, char **argv) {
    if (argc > 1) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        fill_loopback(&a, atoi(argv[1]));
        connect(s, (struct sockaddr *)&a, sizeof a);
        close(s);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 0; ; i++) {
        printf("beat %d patched=%d\n", i, patched());
        usleep(300000);
    }
}
