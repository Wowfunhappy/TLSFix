#import <Foundation/Foundation.h>
#include <sys/stat.h>
static inline void AQRequire(BOOL condition, NSString *message) {
    if(!condition) @throw [NSException exceptionWithName:@"AquaTransportAirDropError" reason:message userInfo:nil];
}
static inline BOOL AQHasTAP(void) {
    struct stat st; return !lstat("/dev/tap0",&st) && S_ISCHR(st.st_mode);
}
