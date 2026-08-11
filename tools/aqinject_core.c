// The injection engine: load a dylib into an already-running process on Mac OS X 10.6-10.9
// (i386 + x86_64), using the target's own dlopen.
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
// THE TWO STAGES ARE BOTH LOAD-BEARING, and they are also what forces the gate sequence in
// aqwatch. Calling dlopen directly from the bare mach thread is not safe, and under a DTrace
// stop() -- a BSD process stop -- pthread_create'd threads are never scheduled, so stage 2
// would be created and never run and dlopen would never be called. That is why aqwatch
// converts the process stop into a Mach suspension of the one gated thread before calling in
// here: by the time this runs, the target is a normally running process with one thread held.
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
// targets and aq_inject_dispatch spawns the matching slice for a target of the other arch.

#include "aqinject_core.h"

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
#include <stdint.h>

#ifndef P_LP64
#define P_LP64 0x00000004
#endif
#ifndef SZOMB
#define SZOMB 5
#endif

extern char **environ;

// Written into the pthread_create-return slot before the thread starts, so that slot reading
// back as 0 means "returned success" rather than "nothing has been stored here yet".
#define PCRET_UNSET 0xFFFFFFFFu

#define PAYLOAD_SZ  0x1000
#define OFF_ATTR    0x080
#define OFF_PATH    0x100
#define OFF_STAGE1  0x400
#define OFF_STAGE2  0x480

// How long to wait for stage 2 to report back, and how closely to watch for it.
//
// The fine interval is what the gate path is worth: the target is frozen for the whole wait, so
// the poll interval is most of the latency the injection adds. At 100 us a cold injection
// against a ready target completes in ~18 ms of wall time, against ~126 ms when the flag is
// checked every 100 ms. It steps back to the coarse interval afterwards, so a target whose
// dlopen is genuinely slow is not polled tens of thousands of times for no gain.
#define POLL_FINE_US    100
#define POLL_FINE_N     200        // 20 ms of fine polling
#define POLL_COARSE_US 1000
#define POLL_TOTAL_MS  5000

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
#define C_PCRET 80
#define C_DE 88
#define C_ERR 96
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
    0x41,0x89,0x47,0x50,                      // mov [r15+80],eax  pthread_create's return
    0xEB,0xFE                                 // 1: jmp 1b
};
static const unsigned char STAGE2[] = {
    0x55, 0x48,0x89,0xE5, 0x49,0x89,0xFF,     // push rbp; mov rbp,rsp; mov r15,rdi
    0x49,0x8B,0x7F,0x18,                      // mov rdi,[r15+24]  path
    0x49,0x8B,0x77,0x20,                      // mov rsi,[r15+32]  mode
    0x49,0x8B,0x47,0x08,                      // mov rax,[r15+8]   dlopen
    0xFF,0xD0,                                // call rax
    0x49,0x89,0x47,0x40,                      // mov [r15+64],rax  handle
    0x48,0x85,0xC0,                           // test rax,rax
    0x75,0x0A,                                // jnz done
    0x49,0x8B,0x47,0x58,                      // mov rax,[r15+88]  dlerror
    0xFF,0xD0,                                // call rax
    0x49,0x89,0x47,0x60,                      // mov [r15+96],rax  the reason, in the target
    0x49,0xC7,0x47,0x38,0x01,0x00,0x00,0x00,  // done: mov qword [r15+56],1
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
#define C_PCRET 40
#define C_DE 44
#define C_ERR 48
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
    0x89,0x46,0x28,                           // mov [esi+40],eax  pthread_create's return
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
    0x85,0xC0,                                // test eax,eax
    0x75,0x0B,                                // jnz done
    0x8B,0x41,0x2C,                           // mov eax,[ecx+44]  dlerror
    0xFF,0xD0,                                // call eax
    0x8B,0x4D,0x08,                           // mov ecx,[ebp+8]   reload (call clobbers ecx)
    0x89,0x41,0x30,                           // mov [ecx+48],eax  the reason, in the target
    0x8B,0x4D,0x08,                           // done: mov ecx,[ebp+8]
    0xC7,0x41,0x1C,0x01,0x00,0x00,0x00,       // mov dword [ecx+28],1  done
    0x31,0xC0, 0xC9, 0xC3                     // xor eax,eax; leave; ret
};
#define MY_LP64 0
#else
#error unsupported arch
#endif

int aq_self_lp64(void) { return MY_LP64; }
int aq_path_fits(const char *path) { return strlen(path) < (OFF_STAGE1 - OFF_PATH); }

int aq_proc_lp64(pid_t pid, int *lp64) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    struct kinfo_proc kp; size_t len = sizeof kp;
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return 0;
    if (lp64) *lp64 = (kp.kp_proc.p_flag & P_LP64) != 0;
    return 1;
}

// Alive in the only sense that matters here: still able to receive a library. A zombie answers
// kill(pid, 0) exactly as a running process does but has already torn down its task, so
// treating it as alive turns every process that exits mid-injection into a task_for_pid
// failure reported as a fault. p_stat is what separates the two.
int aq_alive(pid_t pid) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    struct kinfo_proc kp; size_t len = sizeof kp;
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0) return 0;
    return kp.kp_proc.p_stat != SZOMB;
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

// True if an image whose path contains `needle` is loaded in the target.
int aq_task_has_image(task_t task, const char *needle) {
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

// THE EXEC RACE. A pid appears in the kernel's process list as soon as the process exists,
// which is before dyld has loaded the executable it is going to run. Anything injected in that
// window lands in an address space the following exec throws away: the injection either
// reports success or fails reading back its own payload, and either way the library is not
// there afterwards.
//
// AN IMAGE LIST IS NOT THE CONDITION TO WAIT FOR. dyld publishes infoArray as it loads, so
// infoArrayCount goes positive early in startup -- while dyld is still working and, crucially,
// before libSystem's initializer has run. Injecting in that window asks a process whose pthread
// subsystem is not yet initialized to run pthread_create off a bare mach thread with a
// hand-built TSD. It fails, and it fails in the way that is hardest to see: stage 1 gets a
// non-zero return from pthread_create, stage 2 never runs, no dlopen is ever attempted, and the
// injector sits out its full wait and reports a timeout. On 10.9.5 a com.apple.WebKit.Networking
// launch spends 14-51 ms with an image list published and libSystemInitialized still false.
//
// dyld sets libSystemInitialized once libSystem's initializer has returned, which is precisely
// the condition the payload depends on, so that is what this reports: an observation of the
// target's own state rather than a delay guessed in advance.
static int target_ready(task_t task) {
    task_dyld_info_data_t di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &cnt) != KERN_SUCCESS) return 0;
    if (di.all_image_info_addr == 0) return 0;
    struct dyld_all_image_infos aii; mach_vm_size_t n = 0;
    if (mach_vm_read_overwrite(task, di.all_image_info_addr, sizeof aii,
            (mach_vm_address_t)(uintptr_t)&aii, &n) != KERN_SUCCESS) return 0;
    if (aii.infoArrayCount == 0) return 0;
    // libSystemInitialized exists from all_image_infos version 2 (10.5) on, so it is always
    // present on 10.6-10.9; the guard is only so an unexpected layout degrades to the old
    // behaviour rather than reading a garbage byte as "not ready" forever.
    if (aii.version >= 2 && !aii.libSystemInitialized) return 0;
    return 1;
}

// Returns AQ_OK once the target is ready to be injected, AQ_GONE if it exited on the way
// there, and AQ_FAILED if it is still alive but never became ready.
//
// On the gate path this is a single assertion rather than a wait. A process sitting in
// connect(), accept() or read() finished dyld startup long ago, so a negative answer there is
// not a target to wait for -- it is something unaccounted for, and the useful response is to
// say so and let the process run rather than hold a thread against a condition that is not
// coming.
static int wait_for_exec(task_t task, pid_t pid, const aq_opts *o) {
    if (o->gated) {
        if (target_ready(task)) return AQ_OK;
        if (!aq_alive(pid)) return AQ_GONE;
        fprintf(stderr, "  pid %d: gated at a syscall but not past dyld startup\n", pid);
        return AQ_FAILED;
    }
    for (int i = 0; i < 500; i++) {              // 5s ceiling; normally a handful of iterations
        if (target_ready(task)) return AQ_OK;
        if (!aq_alive(pid)) { if (!o->quiet) fprintf(stderr, "  pid %d: exited before exec\n", pid); return AQ_GONE; }
        usleep(10000);
    }
    fprintf(stderr, "  pid %d: never finished dyld startup\n", pid);
    return aq_alive(pid) ? AQ_FAILED : AQ_GONE;
}

// A mach call against the target failed. If the target has gone, that is why, and it
// is the ordinary end of a short-lived process rather than something to report; otherwise the
// call failed against a live task and the reason is worth printing.
static int mach_step_failed(pid_t pid, const char *what, kern_return_t kr) {
    if (!aq_alive(pid)) return AQ_GONE;
    fprintf(stderr, "  pid %d: %s failed: %s\n", pid, what, mach_error_string(kr));
    return AQ_FAILED;
}

int aq_inject(pid_t pid, const char *path, const aq_opts *o) {
    void *p_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    void *p_pthread_create = dlsym(RTLD_DEFAULT, "pthread_create");
    void *p_dlerror = dlsym(RTLD_DEFAULT, "dlerror");
    if (!p_dlopen || !p_pthread_create || !p_dlerror) {
        fprintf(stderr, "cannot resolve libSystem symbols\n"); return AQ_FAILED;
    }

    // A process on its way out drops its task before it becomes a zombie, so a failure here is
    // ambiguous the instant it happens: the target may be exiting, or it may be mid-exec, or it
    // may be one this tool genuinely cannot open. Giving it a few tries and re-asking whether
    // the target is still there resolves which, and keeps a process that was merely quitting
    // from being reported as a fault.
    task_t task = MACH_PORT_NULL;
    kern_return_t kr = KERN_FAILURE;
    for (int i = 0; i < 5; i++) {
        kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr == KERN_SUCCESS) break;
        if (!aq_alive(pid)) return AQ_GONE;
        usleep(20000);
    }
    if (kr != KERN_SUCCESS) {
        if (!aq_alive(pid)) return AQ_GONE;
        fprintf(stderr, "  pid %d: task_for_pid failed: %s\n", pid, mach_error_string(kr));
        return AQ_FAILED;
    }

    int status = AQ_FAILED;
    thread_act_t th = MACH_PORT_NULL;
    mach_vm_address_t payload = 0, stack = 0, tsd = 0;
    // The bootstrap thread makes exactly one call -- pthread_create -- and then spins, so it
    // needs a fraction of a normal stack. Stage 2 runs on a real pthread with a kernel-provided
    // stack of its own and never touches this one.
    const mach_vm_size_t STACK_SZ = 0x10000, TSD_SZ = 0x8000;

    // Before anything is written into the target: make sure it is running its own image and
    // not still on its way through exec. See the exec-race note above.
    int w = wait_for_exec(task, pid, o);
    if (w != AQ_OK) { status = w; goto out; }

    if (!verify_shared_cache(task, p_dlopen)) {
        if (!o->quiet) fprintf(stderr, "  pid %d: shared-cache mismatch, skipping\n", pid);
        goto out;
    }

    {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#define A(addr, sz, what) do { kr = mach_vm_allocate(task, &addr, sz, VM_FLAGS_ANYWHERE); \
        if (kr != KERN_SUCCESS) { status = mach_step_failed(pid, what, kr); goto out; } } while (0)
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
        put_word(page, C_DE, (word_t)(uintptr_t)p_dlerror);
        // Sentinel, so "pthread_create has not returned yet" is distinguishable from the 0 it
        // returns on success. Stage 1 overwrites the low 32 bits with the actual return.
        put_word(page, C_PCRET, (word_t)PCRET_UNSET);
        memcpy(page + OFF_ATTR,   &attr, sizeof attr);
        memcpy(page + OFF_PATH,   path,  strlen(path) + 1);
        memcpy(page + OFF_STAGE1, STAGE1, sizeof STAGE1);
        memcpy(page + OFF_STAGE2, STAGE2, sizeof STAGE2);

        if ((kr = mach_vm_write(task, payload, (vm_offset_t)(uintptr_t)page, PAYLOAD_SZ)) != KERN_SUCCESS ||
            (kr = mach_vm_protect(task, payload, PAYLOAD_SZ, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != KERN_SUCCESS) {
            status = mach_step_failed(pid, "writing payload", kr);
            goto out;
        }
        word_t self = (word_t)tsd;
        if ((kr = mach_vm_write(task, tsd, (vm_offset_t)(uintptr_t)&self, sizeof self)) != KERN_SUCCESS) {
            status = mach_step_failed(pid, "writing tsd", kr);
            goto out;
        }
    }

#if defined(__x86_64__)
    {
        x86_thread_state64_t st; memset(&st, 0, sizeof st);
        st.__rip = (uint64_t)(payload + OFF_STAGE1);
        st.__r15 = (uint64_t)payload;
        st.__rsp = ((uint64_t)(stack + STACK_SZ - 256)) & ~0xFULL;
        kr = thread_create_running(task, x86_THREAD_STATE64, (thread_state_t)&st, x86_THREAD_STATE64_COUNT, &th);
    }
#else
    {
        x86_thread_state32_t st; memset(&st, 0, sizeof st);
        st.__eip = (uint32_t)(payload + OFF_STAGE1);
        st.__esi = (uint32_t)payload;
        uint32_t sp = (uint32_t)(stack + STACK_SZ - 256); sp &= ~0xFU;
        st.__esp = sp;
        kr = thread_create_running(task, x86_THREAD_STATE32, (thread_state_t)&st, x86_THREAD_STATE32_COUNT, &th);
    }
#endif
    if (kr != KERN_SUCCESS) { status = mach_step_failed(pid, "thread_create_running", kr); goto out; }

    {
        // Wait for stage 2 to report back, but stop the moment the target is unreadable. A
        // process that exits while we are injecting never sets the flag, and without this check
        // the read failure is indistinguishable from "not done yet", so the loop would run its
        // full ceiling against a process that is already gone.
        word_t done = 0, handle = 0;
        int gone = 0;
        long waited_us = 0;
        for (int i = 0; !done && waited_us < (long)POLL_TOTAL_MS * 1000; i++) {
            mach_vm_size_t n = 0;
            if (mach_vm_read_overwrite(task, payload + C_DONE, sizeof done,
                                       (mach_vm_address_t)(uintptr_t)&done, &n) != KERN_SUCCESS) {
                gone = 1; break;
            }
            if (!done) {
                int us = i < POLL_FINE_N ? POLL_FINE_US : POLL_COARSE_US;
                usleep((useconds_t)us);
                waited_us += us;
            }
        }

        // The payload became unreadable. Either the process exited, or it exec'd and took our
        // allocation with it -- distinguished by asking whether it is still there.
        if (gone) {
            if (aq_alive(pid)) {
                if (!o->quiet) fprintf(stderr, "  pid %d: raced with exec, retrying\n", pid);
                status = AQ_RACED;
            } else {
                if (!o->quiet) fprintf(stderr, "  pid %d: exited during injection\n", pid);
                status = AQ_GONE;
            }
            goto out;
        }
        if (done) {
            mach_vm_size_t n = 0;
            mach_vm_read_overwrite(task, payload + C_HAND, sizeof handle, (mach_vm_address_t)(uintptr_t)&handle, &n);
        }

        const char *base = strrchr(path, '/');
        const char *needle = base ? base + 1 : path;

        // Timing out is not the same as failing. Stage 2 runs on a real pthread of the target's
        // own, which this tool does not own and does not stop -- terminating the bootstrap
        // thread below leaves it running -- so a dlopen that has not reported back may still be
        // in progress, and asking the image list is the difference between "not yet" and "no".
        if (!done) {
            if (aq_task_has_image(task, needle) == 1) {
                if (!o->quiet) printf("  pid %d (%s): injected (dlopen outran the wait)\n",
                                      pid, MY_LP64 ? "x86_64" : "i386");
                status = AQ_OK;
                goto out;
            }
            // Which of the two things that can stall here actually did. Stage 1 records what
            // pthread_create returned, so a thread that was never created reads as its errno
            // rather than as a bare wait that expired. The two call for opposite responses -- a
            // target whose dlopen is merely slow wants to be left alone to finish, one whose
            // stage 2 never started wants another attempt -- so they must not print the same
            // line.
            // WHETHER TO TRY AGAIN TURNS ENTIRELY ON WHETHER A STAGE 2 IS ALREADY RUNNING,
            // and getting that wrong wedges the target. dlopen runs the new image's
            // initialisers under a dyld lock; a second dlopen started while the first is still
            // inside it gives the target two threads contending for that lock, and every OTHER
            // thread in the process that so much as triggers a lazy symbol bind queues up
            // behind them. The process stops doing whatever it was doing -- observed here as a
            // multithreaded target that simply stopped, with no thread of ours suspended and
            // nothing frozen: it was stuck on its own linker.
            //
            // Stage 1 records what pthread_create returned, which answers the question exactly:
            //
            //   non-zero   pthread_create FAILED, so no stage 2 exists and nothing holds the
            //              dyld lock. Trying again is safe and is the whole reason for retries.
            //   zero       pthread_create SUCCEEDED. A stage 2 is out there and dlopen has not
            //              come back. Another attempt would be the second dlopen. Leave it be:
            //              the load may still land on its own, and the target keeps working
            //              either way.
            //   unset      stage 1 has not returned yet, so whether a stage 2 exists is
            //              unknown. Treated as "it might" -- the cost of not retrying is one
            //              unpatched process, the cost of retrying wrongly is a wedged one.
            word_t pcret = 0; mach_vm_size_t rn = 0;
            int know_no_stage2 = 0;
            if (mach_vm_read_overwrite(task, payload + C_PCRET, sizeof pcret,
                                       (mach_vm_address_t)(uintptr_t)&pcret, &rn) == KERN_SUCCESS &&
                (uint32_t)pcret != PCRET_UNSET && (uint32_t)pcret != 0) {
                fprintf(stderr, "  pid %d: pthread_create failed in target: %s (%u)\n",
                        pid, strerror((int)(uint32_t)pcret), (unsigned)(uint32_t)pcret);
                know_no_stage2 = 1;
            } else {
                fprintf(stderr, "  pid %d: timed out%s; not retrying, a second dlopen would "
                                "contend for the target's linker lock\n", pid,
                        (uint32_t)pcret == PCRET_UNSET ? " (stage 1 never returned from pthread_create)"
                                                       : " (stage 2 started; dlopen still running)");
            }
            if (!aq_alive(pid))      status = AQ_GONE;
            else if (know_no_stage2) status = AQ_RACED;
            else                     status = AQ_FAILED;
            goto out;
        }
        if (!handle) {
            // dlerror(), read out of the target. "dlopen returned NULL" on its own names no
            // cause and cannot be acted on; dyld's own message says whether the file could not
            // be read, a symbol was missing, or the mapping failed.
            word_t errp = 0; mach_vm_size_t rn = 0;
            char reason[512]; reason[0] = 0;
            if (mach_vm_read_overwrite(task, payload + C_ERR, sizeof errp,
                                       (mach_vm_address_t)(uintptr_t)&errp, &rn) == KERN_SUCCESS && errp) {
                if (mach_vm_read_overwrite(task, (mach_vm_address_t)errp, sizeof reason - 1,
                                           (mach_vm_address_t)(uintptr_t)reason, &rn) != KERN_SUCCESS)
                    reason[0] = 0;
                reason[sizeof reason - 1] = 0;
            }
            fprintf(stderr, "  pid %d: dlopen returned NULL%s%s\n", pid,
                    reason[0] ? ": " : " (dlerror gave no reason)", reason[0] ? reason : "");
            status = AQ_FAILED;
            goto out;
        }

        // Confirm the library is actually in the target rather than trusting that it should be.
        // dlopen can report success into an address space that an exec is about to replace, in
        // which case nothing above notices and the process runs on unpatched.
        //
        // The gate path skips this. It exists to catch that exec, and the gated thread is
        // suspended for the whole injection, so no exec can race it -- there is nothing left
        // for the check to find, and it costs 0.135 ms of a hold on a frozen process.
        if (!o->gated) {
            int present = aq_task_has_image(task, needle);
            if (present != 1) {
                if (!aq_alive(pid)) {
                    if (!o->quiet) fprintf(stderr, "  pid %d: exited during injection\n", pid);
                    status = AQ_GONE;
                } else {
                    if (!o->quiet) fprintf(stderr, "  pid %d: dlopen reported success but the image is absent, retrying\n", pid);
                    status = AQ_RACED;
                }
                goto out;
            }
        }
        if (!o->quiet) printf("  pid %d (%s): injected\n", pid, MY_LP64 ? "x86_64" : "i386");
        status = AQ_OK;
    }

out:
    // WHAT AN INJECTION LEAVES BEHIND MATTERS, because it is left in someone else's process --
    // one that may be forwarding packets, driving a VM, or doing anything else it was busy with.
    // Two things are done about that, and a third was tried and abandoned.
    //
    // The bootstrap stack is small. It exists for one call: stage 1 invokes pthread_create and
    // then spins. Stage 2 runs on a real pthread with a kernel-provided stack and never touches
    // this one, so 64 KB is generous where a megabyte was merely conventional.
    //
    // The payload loses write permission once it is finished with. Reaching AQ_OK means the done
    // flag has already been read back, so nothing will write here again -- and a page that stays
    // both writable and executable for the life of the process is a standing gift to anyone who
    // later finds an arbitrary write in it.
    //
    // WHAT IS DELIBERATELY NOT DONE IS FREEING ANY OF IT, and the reason is worth keeping. It
    // looks safe: wait for stage 2 to report, terminate the bootstrap thread, hand the pages
    // back. It is not. dlopen runs the loaded image's initialisers under a dyld lock whose lock
    // OBJECT lives on the stack of whichever thread holds it and is published to other threads
    // through a global pointer -- so any thread still spinning for that lock dereferences that
    // stack. Meanwhile a stage 2 that blocks in dlopen makes this injection time out and retry,
    // and a retry starts a SECOND stage 2: two dlopens in one target, each able to be the one
    // holding the lock. Unmapping anything under that combination crashes the target, which is
    // exactly what it did -- as a hang first, then as a segfault inside
    // ImageLoader::recursiveSpinLock once the obvious lifetime bug was fixed.
    //
    // So roughly 100 KB per injected process is left behind on purpose. A leak is a cost; a
    // crashed target is a failure of the one promise this tool makes, which is that a process is
    // no worse off for having been patched.
    if (th != MACH_PORT_NULL) thread_terminate(th);
    if (task != MACH_PORT_NULL) {
        if (status == AQ_OK && payload)
            mach_vm_protect(task, payload, PAYLOAD_SZ, 0, VM_PROT_READ | VM_PROT_EXECUTE);
        mach_port_deallocate(mach_task_self(), task);
    }
    return status;
}

int aq_inject_retrying(pid_t pid, const char *path, const aq_opts *o) {
    int r = AQ_FAILED;
    for (int attempt = 0; attempt < 5; attempt++) {
        r = aq_inject(pid, path, o);
        if (r != AQ_RACED) return r;
    }
    if (!o->quiet) fprintf(stderr, "  pid %d: kept racing with exec, giving up\n", pid);
    return AQ_FAILED;
}

int aq_inject_dispatch(pid_t pid, const char *path, const aq_opts *o,
                       const char *sibling, const char *sibling_flag) {
    int lp64 = MY_LP64;
    if (!aq_proc_lp64(pid, &lp64)) {
        if (!o->quiet) fprintf(stderr, "  pid %d: gone\n", pid);
        return AQ_GONE;                          // the target exited; nothing to report
    }
    if (lp64 == MY_LP64) return aq_inject_retrying(pid, path, o);

    if (getenv("AQINJECT_REEXEC")) {
        fprintf(stderr, "  pid %d: missing %s slice\n", pid, lp64 ? "x86_64" : "i386");
        return AQ_FAILED;
    }
    char pidstr[16]; snprintf(pidstr, sizeof pidstr, "%d", pid);
    char *av[8]; int ai = 0;
    av[ai++] = (char *)sibling;
    if (sibling_flag) av[ai++] = (char *)sibling_flag;
    if (o->quiet) av[ai++] = (char *)"-q";
    av[ai++] = pidstr; av[ai++] = (char *)path; av[ai] = NULL;
    posix_spawnattr_t a; posix_spawnattr_init(&a);
    cpu_type_t pref[1] = { lp64 ? CPU_TYPE_X86_64 : CPU_TYPE_X86 }; size_t oc = 0;
    posix_spawnattr_setbinpref_np(&a, 1, pref, &oc);
    setenv("AQINJECT_REEXEC", "1", 1);
    pid_t p; int r = posix_spawn(&p, sibling, NULL, &a, av, environ);
    posix_spawnattr_destroy(&a);
    unsetenv("AQINJECT_REEXEC");
    if (r) { errno = r; perror("  posix_spawn(sibling slice)"); return AQ_FAILED; }
    int st; if (waitpid(p, &st, 0) < 0) return AQ_FAILED;
    return WIFEXITED(st) ? WEXITSTATUS(st) : AQ_FAILED;
}
