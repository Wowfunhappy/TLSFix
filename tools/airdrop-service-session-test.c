/* Offline serialization check: no radio or network access. */
#include <stdio.h>
#include <string.h>
#include "state.h"
#include "tx.h"
#include "wire.h"
int main(void) {
 struct ether_addr mac={{2,0,0,0,0,1}};unsigned char bytes[128];uint16_t first=0;int changed=0;
 for(int i=0;i<8;i++) {
  struct awdl_state state;memset(&state,0,sizeof(state));
  awdl_init_state(&state,"test",&mac,CHAN_OPCLASS_149,clock_time_us());
  int size=awdl_init_service_params_tlv(bytes,&state);
  struct awdl_service_params_tlv *tlv=(void*)bytes;uint16_t sui=le16toh(tlv->sui);
  if(size!=sizeof(*tlv)||!sui){fputs("FAIL: service sessions still advertise a constant zero identifier\n",stderr);return 1;}
  if(i==0)first=sui;else if(first!=sui)changed=1;
  awdl_init_service_params_tlv(bytes,&state);
  if(le16toh(tlv->sui)!=sui){fputs("FAIL: identifier changes without a session change\n",stderr);return 1;}
  awdl_peers_free(state.peers.peers);
 }
 if(!changed){fputs("FAIL: new sessions reuse the service identifier\n",stderr);return 1;}
 puts("PASS: new sessions change service identifier; repeated advertisements preserve it");return 0;
}
