#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "schedule.h"
int main(void) {
 struct awdl_state s; memset(&s,0,sizeof(s));
 s.sync.aw_period=16;s.sync.presence_mode=4;s.sync.last_update=1000000;
 s.channel.enc=AWDL_CHAN_ENC_OPCLASS;
 unsigned char channels[16]={6,0,149,0,0,0,0,0,6,0,149,0,0,0,0,0};
 for(int i=0;i<16;i++)s.channel.sequence[i].opclass.chan_num=channels[i];
 for(int slot=0;slot<16;slot++) {
  uint64_t now=1000000+(uint64_t)slot*65536+30000;
  s.channel.current.opclass.chan_num=channels[slot]==6?149:6;
  assert(awdl_can_send_multicast_in(&s,now,3)!=0);
  s.channel.current=s.channel.sequence[slot];
  assert((awdl_can_send_multicast_in(&s,now,3)==0)==(slot==0||slot==8||slot==10));
 }
 s.channel.current=s.channel.sequence[0];
 assert(awdl_can_send_multicast_in(&s,1001000,3)>0);
 assert(awdl_can_send_multicast_in(&s,1000000+65536-1000,3)<0);
 /* Previously a slot-0 announcement could be injected while still on149. */
 s.channel.current.opclass.chan_num=149;
 assert(awdl_is_multicast_eaw(&s,1030000));
 assert(awdl_can_send_in(&s,1030000,3)==0);
 assert(awdl_can_send_multicast_in(&s,1030000,3)>0);
 puts("PASS: multicast waits for retune, rejects idle/non-multicast slots, preserves guards");
}
