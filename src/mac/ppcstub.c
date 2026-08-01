// PowerPC no-op slice for aquatransport.dylib.
//
// WHY THIS EXISTS
//
// On 10.6 with Rosetta installed, DYLD_INSERT_LIBRARIES reaches the *translated* PPC
// environment, and dyld there treats a missing slice as fatal. Measured on 10.6.8:
//
//     arch -ppc /usr/bin/true                                   -> exit 0
//     DYLD_INSERT_LIBRARIES=<i386+x86_64 only> arch -ppc ...     -> exit 133
//         dyld: could not load inserted library: .../aquatransport.dylib
//
// So without a ppc slice, a system-wide install would stop every PowerPC application
// from launching. This slice exists purely so dyld has something valid to load.
//
// It deliberately does nothing. Hooking Secure Transport under Rosetta would require a
// translated PPC build of LibreSSL and would run all crypto through emulation; PPC apps
// on Snow Leopard are legacy software that predates the TLS they would be gaining, so
// the cost is not worth it. PPC apps keep the stock system stack and simply go unfixed.
//
// Built with gcc-4.2 from Xcode 3.2.6, the last Xcode with PowerPC codegen. Neither
// clang on 10.9 nor a stock 10.6 install can produce this, so the result is vendored
// under deps/ppcstub/ -- see tools/build-ppcstub.sh for the recipe.

// No constructor, no symbols, no dependencies beyond what an empty dylib needs.
static int aquatransport_ppc_stub_unused;
