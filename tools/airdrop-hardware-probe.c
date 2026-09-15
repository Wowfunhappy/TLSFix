#include <stdio.h>
#include "../src/mac/aquatransport_airdrop_hardware.h"
int main(void) { char interface[32]={0}; int supported=hardware_supported(interface,sizeof(interface)); printf("Supported radio and LE controller: %s; interface: %s\n",supported?"yes":"no",supported?interface:"none"); return 0; }
