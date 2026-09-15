#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
static unsigned test_index(const char *name) { return !strcmp(name,"tap0") ? 10 : 0; }
#define if_nametoindex test_index
#include "../src/mac/airdrop/AQSocket.inc"
static unsigned observedScope,observedInterface;
static uint32_t observedAssociation;
static int connection_stub(int fd,const struct sockaddr *address,socklen_t length) {
    assert(fd==42); assert(length==sizeof(struct sockaddr_in6));
    observedScope=((const struct sockaddr_in6 *)address)->sin6_scope_id; return 71;
}
static int connectionx_stub(int fd,const struct sockaddr *source,socklen_t sourceLength,const struct sockaddr *destination,socklen_t length,unsigned interface,uint32_t association,uint32_t *connection) {
    assert(!source && sourceLength==0 && connection==NULL);
    observedInterface=interface; observedAssociation=association;
    return connection_stub(fd,destination,length);
}
int main(void) {
    original_connect=connection_stub; original_connectx=connectionx_stub;
    struct sockaddr_in6 address; memset(&address,0,sizeof(address)); address.sin6_family=AF_INET6; address.sin6_len=sizeof(address); address.sin6_port=htons(8770);
    assert(inet_pton(AF_INET6,"fe80::1234",&address.sin6_addr)==1);
    assert(scoped_connect(42,(void *)&address,sizeof(address))==71 && observedScope==0);
    unsigned a=retain_endpoint(address.sin6_addr,address.sin6_port),b=retain_endpoint(address.sin6_addr,address.sin6_port); assert(a && a==b);
    assert(scoped_connect(42,(void *)&address,sizeof(address))==71 && observedScope==10); assert(address.sin6_scope_id==0);
    address.sin6_port=htons(8771); scoped_connect(42,(void *)&address,sizeof(address)); assert(observedScope==0);
    address.sin6_port=htons(8770);
    assert(scoped_connectx(42,NULL,0,(void *)&address,sizeof(address),4,123,NULL)==71); assert(observedScope==10 && observedInterface==10 && observedAssociation==123);
    release_endpoint(a); scoped_connect(42,(void *)&address,sizeof(address)); assert(observedScope==10);
    release_endpoint(b); scoped_connectx(42,NULL,0,(void *)&address,sizeof(address),4,123,NULL); assert(observedScope==0 && observedInterface==4);
    puts("PASS: registered AirDrop endpoints retain TAP scope; other ports and released endpoints pass through; caller data and connectx arguments preserved");
}
