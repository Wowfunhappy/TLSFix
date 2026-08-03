// aqinject -- load the AquaTransport library into an already-running process on
// Mac OS X 10.6-10.9 (i386 + x86_64).
//
// PURPOSE. AquaTransport is a defensive TLS-compatibility shim: it routes these old systems'
// Secure Transport through a modern OpenSSL so that software on 10.6-10.9 can still reach
// today's TLS 1.2/1.3 servers. This tool loads that library into a process the administrator
// already runs on a machine they own, using the process's own dlopen. It edits no system
// configuration and requires no reboot; a faulty library affects only the target process,
// which simply goes unpatched. It reaches running GUI apps as readily as daemons.
//
// It requires root (task_for_pid) and operates only on local processes on the same machine.
// "inject" below is the precise technical term for loading code via the Mach task API; the
// payload is our own single-purpose compatibility library, loaded with the target's own
// dlopen, not arbitrary code.
//
//   sudo aqinject <pid> <dylib>            load into one process
//   sudo aqinject --all <dylib>            load into every eligible running process
//
// aqwatch (tools/aqwatch.c) drives this tool: it watches the process list for launches and
// calls `aqinject <pid> <dylib>` once for each new process, so processes started after aqwatch
// begins running are covered as well.
//
// MECHANISM. pthread_create_from_mach_thread does not exist until 10.7, so its equivalent is
// built by hand and works identically on 10.6:
//
//   1. task_for_pid for the target task port (needs root).
//   2. Allocate in the target: a payload page (RWX: context + a detached pthread attr + the
//      path + two shellcode blobs), a bootstrap stack, and a TSD page.
//   3. thread_create_running a BARE mach thread on stage-1 shellcode. A bare mach thread has
//      no thread-local storage, and almost all libc (errno, malloc, dyld) faults without it,
//      so stage 1 first sets the %gs base with the thread_fast_set_cthread_self machdep trap
//      (call #3: x86_64 `syscall` rax=0x03000003; i386 `int $0x82` eax=3) pointing at a
//      self-referential TSD page. That is the minimum to make ONE further libc call safe.
//   4. Stage 1's single call is pthread_create(&tid, detached_attr, stage2, &ctx). The kernel
//      builds a real pthread (stack and struct from the kernel, not malloc), so stage 2 has
//      complete TLS.
//   5. Stage 2 calls dlopen(path, RTLD_NOW|RTLD_GLOBAL); our dylib's constructor installs the
//      hooks via fishhook. It records the handle and sets a done flag.
//   6. The injector polls the done flag, then terminates the spinning bootstrap thread.
//
// UNCONDITIONAL. Injection is not gated on the target having loaded Security.framework, and
// nothing here waits for a framework to appear.
//
// It is safe because the dylib links CoreFoundation and Security LAZILY (build-macos.sh), so
// loading it into a process pulls in neither: no framework initializer runs, and CFInitialize
// -- which traps when first run late on a secondary thread -- is never reached. Verified by
// tools/latecheck.c: loaded into a process with no CoreFoundation and no Security, both stay
// absent. The dylib's hooks are rebound by name, which needs nothing loaded, and fishhook
// rebinds the call sites if and when Secure Transport arrives, so the library sits inert in a
// process that never does TLS and starts working the moment one does.
//
// A gate on Security.framework would have to predict *when* a process loads it, which is
// unanswerable: a process loads Security when it first needs TLS, and for Safari's shared
// WebKit networking service that is when the user first navigates, arbitrarily long after
// launch. No timeout is long enough, because there is no deadline to be right about.
//
// dlopen/pthread_create are resolved HERE and reused as target addresses: on 10.6-10.9 the
// dyld shared cache is at the same fixed address in every process of a given arch. To keep
// addresses and the pthread_attr_t layout arch-correct, each fat slice injects only same-arch
// targets and spawns the matching slice for a target of the other arch.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 -o aqinject tools/aqinject.c

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/machine.h>
#include <mach/task_info.h>
#include <mach-o/dyld_images.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <spawn.h>
#include <pthread.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>

#ifndef P_LP64
#define P_LP64 0x00000004
#endif

extern char **environ;

#define PAYLOAD_SZ  0x1000
#define OFF_ATTR    0x080
#define OFF_PATH    0x100
#define OFF_STAGE1  0x400
#define OFF_STAGE2  0x480

// Same circular-dependency deny list as the dylib's own gate (aquatransport_hooks_mac.c):
// these processes implement the trust evaluation our verify path calls.
// Matched as a PREFIX, not an equality: --all reads names from kinfo_proc.kp_proc.p_comm,
// which the kernel truncates to MAXCOMLEN (16). "securityd_service" is 17 characters and
// arrives as "securityd_servic", which no exact comparison against this list can match.
static const char *kDeny[] = { "ocspd", "securityd", "securityd_service", "trustd", 0 };

// ---- per-arch shellcode -------------------------------------------------------------
#if defined(__x86_64__)
typedef uint64_t word_t;
#define C_PC 0
#define C_DL 8
#define C_AT 16
#define C_PA 24
#define C_MO 32
#define C_TID 40
#define C_S2 48
#define C_DONE 56
#define C_HAND 64
#define C_GS 72
static const unsigned char STAGE1[] = {
    0x49,0x8B,0x7F,0x48,                      // mov rdi,[r15+72]  gsbase
    0xB8,0x03,0x00,0x00,0x03,                 // mov eax,0x03000003
    0x0F,0x05,                                // syscall
    0x49,0x8D,0x7F,0x28,                      // lea rdi,[r15+40]  &tid
    0x49,0x8B,0x77,0x10,                      // mov rsi,[r15+16]  attr
    0x49,0x8B,0x57,0x30,                      // mov rdx,[r15+48]  stage2
    0x4C,0x89,0xF9,                           // mov rcx,r15       &ctx
    0x49,0x8B,0x47,0x00,                      // mov rax,[r15+0]   pthread_create
    0xFF,0xD0,                                // call rax
    0xEB,0xFE                                 // 1: jmp 1b
};
static const unsigned char STAGE2[] = {
    0x55, 0x48,0x89,0xE5, 0x49,0x89,0xFF,     // push rbp; mov rbp,rsp; mov r15,rdi
    0x49,0x8B,0x7F,0x18,                      // mov rdi,[r15+24]  path
    0x49,0x8B,0x77,0x20,                      // mov rsi,[r15+32]  mode
    0x49,0x8B,0x47,0x08,                      // mov rax,[r15+8]   dlopen
    0xFF,0xD0,                                // call rax
    0x49,0x89,0x47,0x40,                      // mov [r15+64],rax  handle
    0x49,0xC7,0x47,0x38,0x01,0x00,0x00,0x00,  // mov qword [r15+56],1  done
    0x31,0xC0, 0xC9, 0xC3                     // xor eax,eax; leave; ret
};
#define MY_LP64 1
#elif defined(__i386__)
typedef uint32_t word_t;
#define C_PC 0
#define C_DL 4
#define C_AT 8
#define C_PA 12
#define C_MO 16
#define C_TID 20
#define C_S2 24
#define C_DONE 28
#define C_HAND 32
#define C_GS 36
static const unsigned char STAGE1[] = {
    0xFF,0x76,0x24,                           // push [esi+36]  gsbase (-> [esp+4])
    0x50,                                     // push eax       (dummy ret slot)
    0xB8,0x03,0x00,0x00,0x00,                 // mov eax,3
    0xCD,0x82,                                // int 0x82
    0x83,0xC4,0x08,                           // add esp,8
    0x56,                                     // push esi                 arg4 &ctx
    0xFF,0x76,0x18,                           // push [esi+24]            arg3 stage2
    0xFF,0x76,0x08,                           // push [esi+8]             arg2 attr
    0x8D,0x46,0x14,                           // lea eax,[esi+20]
    0x50,                                     // push eax                 arg1 &tid
    0x8B,0x06,                                // mov eax,[esi]            pthread_create
    0xFF,0xD0,                                // call eax
    0x83,0xC4,0x10,                           // add esp,16
    0xEB,0xFE                                 // 1: jmp 1b
};
static const unsigned char STAGE2[] = {
    0x55, 0x89,0xE5,                          // push ebp; mov ebp,esp
    0x8B,0x4D,0x08,                           // mov ecx,[ebp+8]   &ctx
    0xFF,0x71,0x10,                           // push [ecx+16]     mode
    0xFF,0x71,0x0C,                           // push [ecx+12]     path
    0x8B,0x41,0x04,                           // mov eax,[ecx+4]   dlopen
    0xFF,0xD0,                                // call eax
    0x83,0xC4,0x08,                           // add esp,8
    0x8B,0x4D,0x08,                           // mov ecx,[ebp+8]   reload &ctx
    0x89,0x41,0x20,                           // mov [ecx+32],eax  handle
    0xC7,0x41,0x1C,0x01,0x00,0x00,0x00,       // mov dword [ecx+28],1  done
    0x31,0xC0, 0xC9, 0xC3                     // xor eax,eax; leave; ret
};
#define MY_LP64 0
#else
#error unsupported arch
#endif

static int proc_info(pid_t pid, int *lp64, char *comm, size_t commsz) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    struct kinfo_proc kp; size_t len = sizeof kp;
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return 0;
    if (lp64) *lp64 = (kp.kp_proc.p_flag & P_LP64) != 0;
    if (comm) { strncpy(comm, kp.kp_proc.p_comm, commsz - 1); comm[commsz - 1] = 0; }
    return 1;
}

static void put_word(unsigned char *p, size_t off, word_t v) { memcpy(p + off, &v, sizeof v); }

static int verify_shared_cache(task_t task, void *localfn) {
    mach_vm_size_t n = 0; unsigned char remote[16], local[16];
    memcpy(local, localfn, sizeof local);
    if (mach_vm_read_overwrite(task, (mach_vm_address_t)(uintptr_t)localfn, sizeof remote,
            (mach_vm_address_t)(uintptr_t)remote, &n) != KERN_SUCCESS || n != sizeof remote)
        return 0;
    return memcmp(remote, local, sizeof local) == 0;
}

// Walks the target's dyld_all_image_infos. Returns the number of loaded images, or -1 if the
// list cannot be read -- which is also the state of a process that has not finished exec'ing.
// Structs are native to this slice, which matches the target's arch.
static int target_image_count(task_t task) {
    task_dyld_info_data_t di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &cnt) != KERN_SUCCESS) return -1;
    if (di.all_image_info_addr == 0) return -1;
    struct dyld_all_image_infos aii; mach_vm_size_t n = 0;
    if (mach_vm_read_overwrite(task, di.all_image_info_addr, sizeof aii,
            (mach_vm_address_t)(uintptr_t)&aii, &n) != KERN_SUCCESS) return -1;
    return (int)aii.infoArrayCount;
}

// True if an image whose path contains `needle` is loaded in the target.
static int target_has_image(task_t task, const char *needle) {
    task_dyld_info_data_t di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &cnt) != KERN_SUCCESS) return -1;
    struct dyld_all_image_infos aii; mach_vm_size_t n = 0;
    if (mach_vm_read_overwrite(task, di.all_image_info_addr, sizeof aii,
            (mach_vm_address_t)(uintptr_t)&aii, &n) != KERN_SUCCESS) return -1;
    uint32_t count = aii.infoArrayCount;
    if (count > 4096) count = 4096;
    for (uint32_t i = 0; i < count; i++) {
        struct dyld_image_info info;
        mach_vm_address_t slot = (mach_vm_address_t)(uintptr_t)aii.infoArray + (mach_vm_address_t)(i * sizeof info);
        if (mach_vm_read_overwrite(task, slot, sizeof info,
                (mach_vm_address_t)(uintptr_t)&info, &n) != KERN_SUCCESS) continue;
        char p[1024];
        if (mach_vm_read_overwrite(task, (mach_vm_address_t)(uintptr_t)info.imageFilePath,
                sizeof p, (mach_vm_address_t)(uintptr_t)p, &n) != KERN_SUCCESS) continue;
        p[sizeof p - 1] = 0;
        if (strstr(p, needle)) return 1;
    }
    return 0;
}

static int alive(pid_t pid) { return !(kill(pid, 0) != 0 && errno == ESRCH); }

// THE EXEC RACE. A pid appears in the kernel's process list as soon as the process exists,
// which is before dyld has loaded the executable it is going to run. Anything injected in that
// window lands in an address space the following exec throws away: the injection either
// reports success or fails reading back its own payload, and either way the library is not
// there afterwards. aqwatch sees processes at exactly this moment, so this is the common case,
// not an edge one.
//
// A fixed delay before injecting would only be a guess at how long exec takes. This waits for
// an *observable* state instead -- dyld having published an image list, which happens only
// once the new image is loaded and running -- and inject_native then verifies afterwards that
// the library really is in the target. Both are checks on what happened, not predictions.
//
// Returns 0 once the target is running its own image, 1 if it exits or never gets there.
static int wait_for_exec(task_t task, pid_t pid, int quiet) {
    for (int i = 0; i < 200; i++) {              // generous; normally true on the first read
        if (target_image_count(task) > 0) return 0;
        if (!alive(pid)) { if (!quiet) fprintf(stderr, "  pid %d: exited before exec\n", pid); return 1; }
        usleep(10000);
    }
    if (!quiet) fprintf(stderr, "  pid %d: never published a dyld image list\n", pid);
    return 1;
}

// One injection attempt into a same-arch target. Returns 0 on success, 3 if the target raced
// us (the payload went with an exec) and is still alive, so the caller should try again.
static int inject_native(pid_t pid, const char *path, int quiet) {
    void *p_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    void *p_pthread_create = dlsym(RTLD_DEFAULT, "pthread_create");
    if (!p_dlopen || !p_pthread_create) { fprintf(stderr, "cannot resolve libSystem symbols\n"); return 1; }

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        if (!quiet) fprintf(stderr, "  pid %d: task_for_pid failed: %s\n", pid, mach_error_string(kr));
        return 1;
    }
    // Before anything is written into the target: make sure it is running its own image and
    // not still on its way through exec. See the exec-race note above.
    if (wait_for_exec(task, pid, quiet) != 0) return 1;

    if (!verify_shared_cache(task, p_dlopen)) {
        if (!quiet) fprintf(stderr, "  pid %d: shared-cache mismatch, skipping\n", pid);
        return 1;
    }
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    mach_vm_address_t payload = 0, stack = 0, tsd = 0;
    const mach_vm_size_t STACK_SZ = 0x100000, TSD_SZ = 0x8000;
#define A(addr, sz, what) do { kr = mach_vm_allocate(task, &addr, sz, VM_FLAGS_ANYWHERE); \
    if (kr != KERN_SUCCESS) { fprintf(stderr, "  pid %d: %s failed: %s\n", pid, what, mach_error_string(kr)); return 1; } } while (0)
    A(payload, PAYLOAD_SZ, "vm_allocate payload");
    A(stack,   STACK_SZ,   "vm_allocate stack");
    A(tsd,     TSD_SZ,     "vm_allocate tsd");
#undef A

    unsigned char page[PAYLOAD_SZ];
    memset(page, 0, sizeof page);
    put_word(page, C_PC, (word_t)(uintptr_t)p_pthread_create);
    put_word(page, C_DL, (word_t)(uintptr_t)p_dlopen);
    put_word(page, C_AT, (word_t)(payload + OFF_ATTR));
    put_word(page, C_PA, (word_t)(payload + OFF_PATH));
    put_word(page, C_MO, (word_t)(RTLD_NOW | RTLD_GLOBAL));
    put_word(page, C_S2, (word_t)(payload + OFF_STAGE2));
    put_word(page, C_GS, (word_t)tsd);
    memcpy(page + OFF_ATTR,   &attr, sizeof attr);
    memcpy(page + OFF_PATH,   path,  strlen(path) + 1);
    memcpy(page + OFF_STAGE1, STAGE1, sizeof STAGE1);
    memcpy(page + OFF_STAGE2, STAGE2, sizeof STAGE2);

    if ((kr = mach_vm_write(task, payload, (vm_offset_t)(uintptr_t)page, PAYLOAD_SZ)) != KERN_SUCCESS ||
        (kr = mach_vm_protect(task, payload, PAYLOAD_SZ, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != KERN_SUCCESS) {
        fprintf(stderr, "  pid %d: writing payload failed: %s\n", pid, mach_error_string(kr)); return 1;
    }
    word_t self = (word_t)tsd;
    if ((kr = mach_vm_write(task, tsd, (vm_offset_t)(uintptr_t)&self, sizeof self)) != KERN_SUCCESS) {
        fprintf(stderr, "  pid %d: writing tsd failed: %s\n", pid, mach_error_string(kr)); return 1;
    }

    thread_act_t th = MACH_PORT_NULL;
#if defined(__x86_64__)
    x86_thread_state64_t st; memset(&st, 0, sizeof st);
    st.__rip = (uint64_t)(payload + OFF_STAGE1);
    st.__r15 = (uint64_t)payload;
    st.__rsp = ((uint64_t)(stack + STACK_SZ - 256)) & ~0xFULL;
    kr = thread_create_running(task, x86_THREAD_STATE64, (thread_state_t)&st, x86_THREAD_STATE64_COUNT, &th);
#else
    x86_thread_state32_t st; memset(&st, 0, sizeof st);
    st.__eip = (uint32_t)(payload + OFF_STAGE1);
    st.__esi = (uint32_t)payload;
    uint32_t sp = (uint32_t)(stack + STACK_SZ - 256); sp &= ~0xFU;
    st.__esp = sp;
    kr = thread_create_running(task, x86_THREAD_STATE32, (thread_state_t)&st, x86_THREAD_STATE32_COUNT, &th);
#endif
    if (kr != KERN_SUCCESS) { fprintf(stderr, "  pid %d: thread_create_running failed: %s\n", pid, mach_error_string(kr)); return 1; }

    // Wait for stage 2 to report back, but stop the moment the target is unreadable. A
    // process that exits while we are injecting never sets the flag, and without this check
    // the read failure is indistinguishable from "not done yet", so the loop ran its full
    // 200 x 100ms = 20 seconds. Short-lived processes are the common case under aqwatch --
    // every shell command is one -- and each such injector held one of aqwatch's in-flight
    // slots for those 20 seconds, which is enough on its own to pin the cap and delay
    // injection into the processes that do matter.
    word_t done = 0, handle = 0;
    int gone = 0;
    for (int i = 0; i < 200 && !done; i++) {
        mach_vm_size_t n = 0;
        if (mach_vm_read_overwrite(task, payload + C_DONE, sizeof done,
                                   (mach_vm_address_t)(uintptr_t)&done, &n) != KERN_SUCCESS) {
            gone = 1; break;
        }
        if (!done) usleep(100000);
    }
    // The payload became unreadable. Either the process exited, or it exec'd and took our
    // allocation with it -- distinguished by asking whether it is still there.
    if (gone) {
        thread_terminate(th);
        if (alive(pid)) {
            if (!quiet) fprintf(stderr, "  pid %d: raced with exec, retrying\n", pid);
            return 3;
        }
        if (!quiet) fprintf(stderr, "  pid %d: exited during injection\n", pid);
        return 2;
    }
    if (done) {
        mach_vm_size_t n = 0;
        mach_vm_read_overwrite(task, payload + C_HAND, sizeof handle, (mach_vm_address_t)(uintptr_t)&handle, &n);
    }
    thread_terminate(th);

    if (!done)   { fprintf(stderr, "  pid %d: timed out\n", pid); return alive(pid) ? 3 : 2; }
    if (!handle) { fprintf(stderr, "  pid %d: dlopen returned NULL\n", pid); return 1; }

    // Confirm the library is actually in the target rather than trusting that it should be.
    // dlopen can report success into an address space that an exec is about to replace, in
    // which case nothing above notices and the process runs on unpatched -- which is exactly
    // how this failed for Safari's networking service. Checking the image list is the only
    // statement about the outcome that is worth anything.
    const char *base = strrchr(path, '/');
    int present = target_has_image(task, base ? base + 1 : path);
    if (present != 1) {
        if (!alive(pid)) { if (!quiet) fprintf(stderr, "  pid %d: exited during injection\n", pid); return 2; }
        if (!quiet) fprintf(stderr, "  pid %d: dlopen reported success but the image is absent, retrying\n", pid);
        return 3;
    }

    printf("  pid %d (%s): injected\n", pid, MY_LP64 ? "x86_64" : "i386");
    return 0;
}

// Retries only the one failure that is worth retrying: the target raced us through exec and is
// still alive. That is a detected outcome, not a timer -- each attempt re-acquires the task
// port, so the retry works against the post-exec address space.
static int inject_native_retrying(pid_t pid, const char *path, int quiet) {
    int r = 1;
    for (int attempt = 0; attempt < 5; attempt++) {
        r = inject_native(pid, path, quiet);
        if (r != 3) return r;
    }
    if (!quiet) fprintf(stderr, "  pid %d: kept racing with exec, giving up\n", pid);
    return 1;
}

// Inject into any target, spawning the matching fat slice when the target is the other arch.
static int inject_dispatch(pid_t pid, const char *path) {
    int lp64 = MY_LP64;
    if (!proc_info(pid, &lp64, NULL, 0)) { fprintf(stderr, "  pid %d: gone\n", pid); return 1; }
    if (lp64 == MY_LP64) return inject_native_retrying(pid, path, 0);

    if (getenv("AQINJECT_REEXEC")) { fprintf(stderr, "  pid %d: missing %s slice\n", pid, lp64 ? "x86_64" : "i386"); return 1; }
    char self[4096]; uint32_t sz = sizeof self;
    if (_NSGetExecutablePath(self, &sz) != 0) return 1;
    char pidstr[16]; snprintf(pidstr, sizeof pidstr, "%d", pid);
    char *av[8]; int ai = 0;
    av[ai++] = self;
    av[ai++] = pidstr; av[ai++] = (char *)path; av[ai] = NULL;
    posix_spawnattr_t a; posix_spawnattr_init(&a);
    cpu_type_t pref[1] = { lp64 ? CPU_TYPE_X86_64 : CPU_TYPE_X86 }; size_t oc = 0;
    posix_spawnattr_setbinpref_np(&a, 1, pref, &oc);
    setenv("AQINJECT_REEXEC", "1", 1);
    pid_t p; int r = posix_spawn(&p, self, NULL, &a, av, environ);
    posix_spawnattr_destroy(&a);
    unsetenv("AQINJECT_REEXEC");
    if (r) { errno = r; perror("  posix_spawn(sibling slice)"); return 1; }
    int st; if (waitpid(p, &st, 0) < 0) return 1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

static int is_denied(const char *comm) {
    // Prefix match, because comm may be a MAXCOMLEN-truncated p_comm (see kDeny).
    for (int i = 0; kDeny[i]; i++) if (!strncmp(comm, kDeny[i], strlen(comm))) return 1;
    return 0;
}

static int inject_all(const char *path) {
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0) { perror("sysctl size"); return 1; }
    struct kinfo_proc *procs = malloc(len);
    if (!procs || sysctl(mib, 3, procs, &len, NULL, 0) != 0) { perror("sysctl list"); free(procs); return 1; }
    int count = (int)(len / sizeof(struct kinfo_proc));

    pid_t me = getpid();
    int done = 0, skipped = 0, failed = 0;
    for (int i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        const char *comm = procs[i].kp_proc.p_comm;
        if (pid <= 1 || pid == me) continue;
        if (is_denied(comm)) { skipped++; continue; }
        int r = inject_dispatch(pid, path);
        if (r == 0) done++;
        else if (r == 2) skipped++;    // exited during injection
        else failed++;
    }
    free(procs);
    printf("done: %d injected, %d skipped, %d failed\n", done, skipped, failed);
    return 0;
}

int main(int argc, char **argv) {
    int all = 0, ai = 1;
    for (; ai < argc; ai++) {
        if (!strcmp(argv[ai], "--all")) all = 1;
        else break;
    }
    if (all) {
        if (ai != argc - 1) { fprintf(stderr, "usage: %s --all <dylib>\n", argv[0]); return 2; }
        return inject_all(argv[ai]);
    }
    if (argc - ai != 2) {
        fprintf(stderr, "usage: %s <pid> <dylib>\n"
                        "       %s --all <dylib>\n", argv[0], argv[0]);
        return 2;
    }
    pid_t pid = (pid_t)atoi(argv[ai]);
    const char *path = argv[ai + 1];
    if (strlen(path) >= (OFF_STAGE1 - OFF_PATH)) { fprintf(stderr, "path too long\n"); return 2; }
    return inject_dispatch(pid, path);
}
