// Runtime symbol presence check. Replaces `nm` for probing older systems, because a
// stock Mac OS X install has no developer tools -- 10.6 ships lipo but not nm or otool,
// which silently turned every nm-based check into a false "MISSING".
//
// dlsym is also the more honest test: it answers "can this be resolved at runtime in
// this process", which is exactly what the hooks depend on.
//
//   clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
//       -framework Security -framework CoreFoundation -o symprobe tools/symprobe.c
//
//   ./symprobe SSLHandshake SecKeyRawSign ...

#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv) {
    int missing = 0;
    for (int i = 1; i < argc; i++) {
        void *p = dlsym(RTLD_DEFAULT, argv[i]);
        printf("  %-38s %s\n", argv[i], p ? "PRESENT" : "MISSING");
        if (!p) missing++;
    }
    if (argc > 1) printf("  (%d of %d missing)\n", missing, argc - 1);
    return missing ? 1 : 0;
}
