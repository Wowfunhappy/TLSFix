/* Offline valid peer announcements: the weak peer must not win election. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "core.h"
#include "tx.h"
#include "rx.h"
#include "ieee80211.h"
static int announce(struct awdl_state *receiver,struct awdl_state *sender,int rssi) {
 unsigned char bytes[4096];struct ieee80211_state wire;memset(&wire,0,sizeof(wire));ieee80211_init_state(&wire);
 int n=awdl_init_full_action_frame(bytes,sender,&wire,AWDL_ACTION_MIF);
 int offset=bytes[2]+256*bytes[3]+sizeof(struct ieee80211_hdr);
 const struct buf *frame=buf_new_const(bytes+offset,n-offset);
 int result=awdl_rx_action(frame,rssi,clock_time_us(),&sender->self_address,&receiver->self_address,receiver);
 buf_free(frame);return result;
}
int main(void) {
 struct awdl_state receiver,phone,weak;memset(&receiver,0,sizeof(receiver));memset(&phone,0,sizeof(phone));memset(&weak,0,sizeof(weak));
 struct ether_addr a={{2,0,0,0,0,1}},b={{2,0,0,0,0,2}},c={{2,0,0,0,0,3}};
 awdl_init_state(&receiver,"receiver",&a,CHAN_OPCLASS_149,clock_time_us());
 awdl_init_state(&phone,"near",&b,CHAN_OPCLASS_149,clock_time_us());
 awdl_init_state(&weak,"weak",&c,CHAN_OPCLASS_149,clock_time_us());
 phone.election.master_counter=phone.election.self_counter=100;
 weak.election.master_counter=weak.election.self_counter=10000;
 assert(receiver.filter_rssi);
 assert(announce(&receiver,&weak,-81)==RX_IGNORE_RSSI);
 assert(announce(&receiver,&phone,-80)==RX_OK);
 /* Captured iOS announcements were consistently -70/-71 dBm. The old
  * -65 dBm admission threshold discarded every one before discovery. */
 assert(announce(&receiver,&phone,-71)==RX_OK);
 assert(announce(&receiver,&weak,-85)==RX_IGNORE_RSSI);
 awdl_election_run(&receiver.election,&receiver.peers);
 assert(!compare_ether_addr(&receiver.election.sync_addr,&b));
 assert(announce(&receiver,&phone,-85)==RX_OK); /* Existing-peer grace. */
 assert(announce(&receiver,&phone,-86)==RX_IGNORE_RSSI);
 receiver.filter_rssi=0;assert(announce(&receiver,&weak,-85)==RX_OK);
 awdl_election_run(&receiver.election,&receiver.peers);
 assert(!compare_ether_addr(&receiver.election.sync_addr,&c));
 awdl_peers_free(receiver.peers.peers);awdl_peers_free(phone.peers.peers);awdl_peers_free(weak.peers.peers);
 puts("PASS: admits captured iPhone signal, retains bounded grace, rejects weak timing master");
}
