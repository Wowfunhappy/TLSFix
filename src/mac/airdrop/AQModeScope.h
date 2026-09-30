#ifndef AQ_MODE_SCOPE_H
#define AQ_MODE_SCOPE_H
/* Standalone fixtures include adapter fragments without the sharingd mode
 * controller. They exercise modern mode by default. */
#ifndef AQ_NATIVE_MODE
#define AQ_NATIVE_MODE 0
#endif
#ifndef AQ_APPLY_PENDING_MODE
#define AQ_APPLY_PENDING_MODE() ((void)0)
#endif
#endif
