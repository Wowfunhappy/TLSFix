// Shared by every gate test subject.
//
// Each one prints its own patched state immediately before and after the syscall the gate is
// supposed to hold it at. That pair is the whole assertion: patched=0 before, patched=1 after,
// the syscall successful, no EINTR, and any payload intact. A subject that reports patched=1
// before the syscall proves nothing -- it was already carrying the library -- so the tests
// treat that as a failure too.

#ifndef GATETEST_H
#define GATETEST_H

#include <arpa/inet.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int patched(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *p = _dyld_get_image_name(i);
        if (p && strstr(p, "aquatransport.dylib")) return 1;
    }
    return 0;
}

static void fill_loopback(struct sockaddr_in *a, int port) {
    memset(a, 0, sizeof *a);
    a->sin_len = sizeof *a;
    a->sin_family = AF_INET;
    a->sin_port = htons((unsigned short)port);
    a->sin_addr.s_addr = inet_addr("127.0.0.1");
}

#endif
