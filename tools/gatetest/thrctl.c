// Suspend or resume a thread of another process, by index, and exit immediately -- so
// "suspend" models a daemon that dies while holding a thread. Used by the suspend-count scan
// test, which needs a hold that no journal knows about.
//
//   sudo thrctl <pid> suspend|resume [index]

#include <mach/mach.h>
#include <mach/thread_act.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <pid> suspend|resume [index]\n", argv[0]); return 2; }
    pid_t pid = (pid_t)atoi(argv[1]);
    int idx = argc > 3 ? atoi(argv[3]) : 0;

    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "task_for_pid: %s\n", mach_error_string(kr)); return 1; }
    thread_act_array_t list; mach_msg_type_number_t n;
    if ((kr = task_threads(task, &list, &n)) != KERN_SUCCESS) { fprintf(stderr, "task_threads\n"); return 1; }
    if (idx >= (int)n) { fprintf(stderr, "only %u threads\n", n); return 1; }
    kr = strcmp(argv[2], "suspend") == 0 ? thread_suspend(list[idx]) : thread_resume(list[idx]);
    printf("%s thread %d of %u: %s\n", argv[2], idx, n, mach_error_string(kr));
    return kr != KERN_SUCCESS;
}
