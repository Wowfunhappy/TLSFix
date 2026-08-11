// Stands in for launchd's inetd mode: accept a connection, then spawn the child with that
// already-connected socket as fd 0.
//
//   inetdlauncher <port> <child>
//
// The launcher itself is gated at its own accept, which is not what is being tested -- the
// child is. It is named so the test can tell the two apart in the daemon's log.

#include "gatetest.h"

#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <port> <child>\n", argv[0]); return 2; }
    int port = atoi(argv[1]);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    fill_loopback(&a, port);
    if (bind(ls, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    listen(ls, 8);
    printf("listening\n");
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { perror("accept"); return 1; }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fd, 0);
    char *av[] = { argv[2], NULL };
    pid_t p = 0;
    if (posix_spawn(&p, argv[2], &fa, NULL, av, environ) != 0) { perror("spawn"); return 1; }
    posix_spawn_file_actions_destroy(&fa);
    close(fd);
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
