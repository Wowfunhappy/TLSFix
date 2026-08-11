// Concurrent gates on one process: several threads connect at the same instant, so they all
// reach the gate before any injection has finished.
//
//   manygates <port>
//
// This is the case the confirmed-patched set cannot help with, because the set is only written
// after an injection completes -- so without a claim per process, every one of these threads
// starts its own injection. Measured on a live machine before that was fixed: vmnet-natd, a
// multithreaded daemon, was injected six times from a single gate storm.
//
// twogates covers the sequential case and passes either way, which is exactly why it missed
// this: the threads there are joined one at a time, so the second always finds the set populated.
// The assertion is on the daemon's log, not on this program's output: one "patched at gate" line
// for this pid, however many threads raced.

#include "gatetest.h"

#include <pthread.h>

#define THREADS 8

static int g_port;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_go = PTHREAD_COND_INITIALIZER;
static int g_release;

static void *racer(void *arg) {
    (void)arg;
    // Everyone waits on one condition and is let go together, so the connects land in the same
    // instant rather than merely close together.
    pthread_mutex_lock(&g_lock);
    while (!g_release) pthread_cond_wait(&g_go, &g_lock);
    pthread_mutex_unlock(&g_lock);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    fill_loopback(&a, g_port);
    connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    g_port = atoi(argv[1]);

    printf("before  patched=%d\n", patched());
    fflush(stdout);

    pthread_t t[THREADS];
    for (int i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, racer, NULL);
    usleep(200000);                       // let them all reach the wait
    pthread_mutex_lock(&g_lock);
    g_release = 1;
    pthread_cond_broadcast(&g_go);
    pthread_mutex_unlock(&g_lock);
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);

    printf("after   %d threads raced the gate patched=%d\n", THREADS, patched());
    fflush(stdout);
    return 0;
}
