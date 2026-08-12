// Self-signed Safari extension support for AquaTransport (Safari on 10.9).
//
// Legacy .safariextz extensions must be signed by an Apple-issued Safari Developer
// certificate, and Apple stopped issuing those years ago. A self-signed certificate can
// stand in, but Safari.framework rejects it in two independent places. This neutralises
// both by patching Safari's own code in memory, so a self-signed extension installs and
// then stays installed.
//
//   1. Certificate::hasInvalidAppleCertificateChain gates installation: a non-Apple chain
//      is refused. Rewritten to report every chain as valid (xor eax, eax; ret).
//
//   2. InstalledExtensionCertificateRevocationHandler::revocationCheckCompleted runs from a
//      deferred certificate-revocation check. On a non-zero status it shows the "extension
//      is no longer valid" alert, then uninstalls the extension and deletes its data. That
//      path does not consult check (1), so it would undo the install on its own schedule.
//      The handler opens with a `je` that skips the uninstall when the status is zero;
//      turning that `je` into an unconditional `jmp` makes every status take the skip, so no
//      revocation verdict can uninstall an extension.
//
// Why byte patching rather than fishhook, which the rest of AquaTransport uses: these are
// internal Safari.framework routines reached by direct call, not exported C entry points with
// rebindable call sites. (1) is an exported C++ symbol, resolved by name; (2) is a local
// symbol, located by the byte signature of its prologue.
//
// Scope. This only ever acts in the Safari UI process (getprogname) and only touches
// Safari.framework, which is mapped into that process alongside Security. In every other
// process the name check returns first. The constructor applies it before Safari's own code
// runs, so the patch is in place before any extension loads or any revocation check fires.
//
//   enforce-apple-safari-ext-chain -- leave Apple's checks in force (apply neither patch), so
//     Safari again demands an Apple-signed extension. Off by default.

#include "aquatransport_config.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Copy-on-write the code page, write the bytes, restore read/execute. VM_PROT_COPY forces a
// private anonymous copy, so the write is not backed by the signed file and stays put.
static int overwrite_code(void *target, const uint8_t *bytes, size_t length) {
    mach_vm_size_t pageSize = (mach_vm_size_t)getpagesize();
    mach_vm_address_t firstPage = ((mach_vm_address_t)(uintptr_t)target) & ~(pageSize - 1);
    mach_vm_address_t lastPage =
        (((mach_vm_address_t)(uintptr_t)target + length - 1)) & ~(pageSize - 1);
    mach_vm_size_t span = (lastPage - firstPage) + pageSize;

    if (mach_vm_protect(mach_task_self(), firstPage, span, false,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return 0;

    memcpy(target, bytes, length);
    mach_vm_protect(mach_task_self(), firstPage, span, false, VM_PROT_READ | VM_PROT_EXECUTE);
    return 1;
}

#if defined(__x86_64__)
// The __TEXT,__text range of an image in memory, from its mach header. Walks load commands
// only -- no getsectiondata(), which postdates the 10.6 deployment target.
static const uint8_t *text_section(const void *machHeader, size_t *outSize) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)machHeader;
    const uint8_t *cmd = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                uintptr_t slide = (uintptr_t)mh - (uintptr_t)seg->vmaddr;
                const struct section_64 *sect = (const struct section_64 *)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strcmp(sect[s].sectname, "__text") == 0) {
                        *outSize = (size_t)sect[s].size;
                        return (const uint8_t *)(uintptr_t)(sect[s].addr + slide);
                    }
                }
            }
        }
        cmd += lc->cmdsize;
    }
    return NULL;
}

// First occurrence of needle in hay. memmem() is 10.7+ and the build forbids it, so this is
// a plain scan.
static uint8_t *find_bytes(const uint8_t *hay, size_t haylen, const uint8_t *needle, size_t nlen) {
    if (nlen == 0 || haylen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= haylen; i++)
        if (memcmp(hay + i, needle, nlen) == 0)
            return (uint8_t *)(hay + i);
    return NULL;
}
#endif

void tf_safariext_install(void) {
    const char *pn = getprogname();
    if (!pn || strcmp(pn, "Safari") != 0)
        return;
    if (tf_flag("enforce-apple-safari-ext-chain")) {
        tf_log("safariext: enforce-apple-safari-ext-chain set, leaving Safari checks in force");
        return;
    }

    // Certificate::hasInvalidAppleCertificateChain(double, Certificate const*) const
    uint8_t *hasInvalidChain =
        (uint8_t *)dlsym(RTLD_DEFAULT, "_ZNK6Safari11Certificate31hasInvalidAppleCertificateChainEdPKS0_");
    if (!hasInvalidChain) {
        tf_log("safariext: hasInvalidAppleCertificateChain not found, not patching");
        return;
    }

    const uint8_t prologue[]    = { 0x55, 0x48, 0x89 };   // push rbp; mov rbp, rsp
    const uint8_t returnFalse[] = { 0x31, 0xc0, 0xc3 };   // xor eax, eax; ret
    if (memcmp(hasInvalidChain, prologue, sizeof prologue) == 0)
        tf_log("safariext: install patch %s", overwrite_code(hasInvalidChain, returnFalse, sizeof returnFalse) ? "applied" : "FAILED");
    else if (memcmp(hasInvalidChain, returnFalse, sizeof returnFalse) != 0)
        tf_log("safariext: unexpected bytes at hasInvalidAppleCertificateChain, not patching");

#if defined(__x86_64__)
    // InstalledExtensionCertificateRevocationHandler::revocationCheckCompleted opens with
    //   push rbp; mov rbp, rsp; push rbx; push rax; mov rbx, rdi; test edx, edx; je <skip>
    // Flip the je (0x74) to jmp (0xeb) so the uninstall is always skipped.
    Dl_info info;
    if (dladdr(hasInvalidChain, &info) && info.dli_fbase) {
        size_t textSize = 0;
        const uint8_t *text = text_section(info.dli_fbase, &textSize);
        if (text) {
            const uint8_t signature[] = {
                0x55, 0x48, 0x89, 0xe5, 0x53, 0x50, 0x48, 0x89, 0xfb, 0x85, 0xd2, 0x74
            };
            uint8_t *match = find_bytes(text, textSize, signature, sizeof signature);
            if (match) {
                uint8_t *je = match + sizeof signature - 1;   // the 0x74
                const uint8_t jmp[] = { 0xeb };
                tf_log("safariext: revocation patch %s", overwrite_code(je, jmp, sizeof jmp) ? "applied" : "FAILED");
            } else {
                tf_log("safariext: revocation handler signature not found, not patching");
            }
        }
    }
#endif
}
