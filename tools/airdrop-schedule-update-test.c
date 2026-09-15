/* Offline valid action-frame replay; no radio, sockets or peer traffic. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "core.h"
#include "tx.h"
static void receive(struct daemon_state *receiver, struct awdl_state *sender, struct ieee80211_state *wire) {
 unsigned char bytes[4096];int size=awdl_init_full_action_frame(bytes,sender,wire,AWDL_ACTION_MIF);
 assert(size>0 && size<(int)sizeof(bytes));struct pcap_pkthdr h;memset(&h,0,sizeof(h));h.caplen=h.len=size;
 awdl_receive_frame((unsigned char*)receiver,&h,bytes);
}
int main(void) {
 struct daemon_state receiver;struct awdl_state sender;struct ieee80211_state wire;
 memset(&receiver,0,sizeof(receiver));memset(&sender,0,sizeof(sender));memset(&wire,0,sizeof(wire));
 struct ether_addr mac={{2,0,0,0,0,1}},phone={{2,0,0,0,0,2}};
 awdl_init_state(&receiver.awdl_state,"receiver",&mac,CHAN_OPCLASS_149,clock_time_us());
 awdl_init_state(&sender,"sender",&phone,CHAN_OPCLASS_149,clock_time_us());ieee80211_init_state(&wire);
 receiver.io.wlan_is_file=1;receiver.awdl_state.follow_master_chanseq=1;receiver.awdl_state.election.sync_addr=phone;
 receive(&receiver,&sender,&wire);
 assert(receiver.awdl_state.stats.rx_action==1);
 /* Low-power social slots can change between maintenance timer firings. */
 for(int round=0;round<3;round++) {
  for(int i=0;i<16;i++) sender.channel.sequence[i]=CHAN_NULL;
  sender.channel.sequence[round*2]=CHAN_OPCLASS_6;
  sender.channel.sequence[round*2+8]=CHAN_OPCLASS_149;
  receive(&receiver,&sender,&wire);
  if(memcmp(receiver.awdl_state.channel.sequence,sender.channel.sequence,sizeof(sender.channel.sequence))) {
   fprintf(stderr,"FAIL: received schedule remains stale until peer maintenance timer\n");return 1;
  }
 }
 /* Following is opt-in. Receiving another update must preserve fixed mode. */
 receiver.awdl_state.follow_master_chanseq=0;
 struct awdl_chan saved[16];memcpy(saved,receiver.awdl_state.channel.sequence,sizeof(saved));
 awdl_chanseq_init_static(sender.channel.sequence,&sender.channel.master);receive(&receiver,&sender,&wire);
 assert(!memcmp(saved,receiver.awdl_state.channel.sequence,sizeof(saved)));
 awdl_peers_free(receiver.awdl_state.peers.peers);awdl_peers_free(sender.peers.peers);
 puts("PASS: master schedule adopted during receive; fixed mode preserved");return 0;
}
