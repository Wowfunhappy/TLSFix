#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sync.h"
int main(void) {
 struct awdl_rx_clock c={0};
 /* Captured consecutive frames: the first packet in a delayed batch used
  * arrival time, then the following packet jumped backwards by 86 ms. */
 uint64_t hardware[]={735028792,735141068,735175924,735240665,735262229,735306851};
 uint64_t host[]={248332190597ULL,248332315370ULL,248332488092ULL,248332488136ULL,248332488150ULL,248332488163ULL};
 uint64_t previous=0;
 for(unsigned i=0;i<sizeof(host)/sizeof(host[0]);i++) {
  uint64_t corrected=awdl_rx_clock_time(&c,hardware[i],host[i]);
  assert(corrected<=host[i]);
  if(i) {
   int64_t error=(int64_t)(corrected-previous)-(int64_t)(hardware[i]-hardware[i-1]);
   if(corrected<=previous || error>2000 || error< -2000) {
    fprintf(stderr,"FAIL: delayed batch distorts receive time at sample %u (error %lld us)\n",i,(long long)error);return 1;
   }
  }
  previous=corrected;
 }
 /* Missing timestamps and a genuine radio-clock restart retain fallback. */
 assert(awdl_rx_clock_time(&c,0,host[5]+1000)==host[5]+1000);
 assert(awdl_rx_clock_time(&c,1000,host[5]+2000)==host[5]+2000);
 puts("PASS: captured delayed batch preserves timing; missing/restarted clocks handled");
 return 0;
}
