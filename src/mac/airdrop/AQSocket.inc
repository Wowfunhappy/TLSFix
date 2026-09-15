/* Preserve the TAP scope lost by Mavericks CFNetwork's URL resolution.
 * Only endpoints resolved by the AirDrop browser are eligible. */
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
static int (*original_connect)(int,const struct sockaddr *,socklen_t);
/* Darwin 13 connectx ABI (pre-sa_endpoints_t). */
static int (*original_connectx)(int,const struct sockaddr *,socklen_t,const struct sockaddr *,socklen_t,unsigned,uint32_t,uint32_t *);
static pthread_mutex_t endpoint_lock=PTHREAD_MUTEX_INITIALIZER;
static struct { struct in6_addr address; uint16_t port; uint32_t scope; unsigned refs; } endpoints[256];
static unsigned retain_endpoint(struct in6_addr address,uint16_t port) {
    unsigned token=0; uint32_t scope=if_nametoindex("tap0"); if(!scope) return 0;
    address.s6_addr[2]=address.s6_addr[3]=0;
    pthread_mutex_lock(&endpoint_lock);
    for(unsigned i=0;i<256;i++) if(endpoints[i].refs && endpoints[i].port==port && endpoints[i].scope==scope && !memcmp(&address,&endpoints[i].address,16)) { token=i+1; break; }
    if(!token) for(unsigned i=0;i<256;i++) if(!endpoints[i].refs) { endpoints[i].address=address; endpoints[i].port=port; endpoints[i].scope=scope; token=i+1; break; }
    if(token) endpoints[token-1].refs++;
    pthread_mutex_unlock(&endpoint_lock); return token;
}
static void release_endpoint(unsigned token) {
    if(!token || token>256) return;
    pthread_mutex_lock(&endpoint_lock); if(endpoints[token-1].refs) endpoints[token-1].refs--; pthread_mutex_unlock(&endpoint_lock);
}
static int scoped_connect(int fd,const struct sockaddr *address,socklen_t length) {
    if(address && length>=sizeof(struct sockaddr_in6) && address->sa_family==AF_INET6) {
        struct sockaddr_in6 scoped; memcpy(&scoped,address,sizeof(scoped));
        if(IN6_IS_ADDR_LINKLOCAL(&scoped.sin6_addr)) {
            struct in6_addr normalized=scoped.sin6_addr; normalized.s6_addr[2]=normalized.s6_addr[3]=0;
            uint32_t scope=0;
            pthread_mutex_lock(&endpoint_lock);
            for(unsigned i=0;i<256;i++) if(endpoints[i].refs && endpoints[i].port==scoped.sin6_port && !memcmp(&normalized,&endpoints[i].address,16)) { scope=endpoints[i].scope; break; }
            pthread_mutex_unlock(&endpoint_lock);
            if(scope) {
#ifdef AQ_SOCKET_DIAGNOSTICS
                fprintf(stderr,"AirDrop socket scope %u -> %u, port %u\n",scoped.sin6_scope_id,scope,ntohs(scoped.sin6_port));
#endif
                scoped.sin6_addr=normalized; scoped.sin6_scope_id=scope; return original_connect(fd,(const struct sockaddr *)&scoped,sizeof(scoped)); }
        }
    }
    return original_connect(fd,address,length);
}
static int scoped_connectx(int fd,const struct sockaddr *source,socklen_t sourceLength,const struct sockaddr *destination,socklen_t length,unsigned interface,uint32_t association,uint32_t *connection) {
    if(destination && length>=sizeof(struct sockaddr_in6) && destination->sa_family==AF_INET6) {
        struct sockaddr_in6 scoped; memcpy(&scoped,destination,sizeof(scoped));
        if(IN6_IS_ADDR_LINKLOCAL(&scoped.sin6_addr)) {
            struct in6_addr normalized=scoped.sin6_addr; normalized.s6_addr[2]=normalized.s6_addr[3]=0;
            uint32_t scope=0;
            pthread_mutex_lock(&endpoint_lock);
            for(unsigned i=0;i<256;i++) if(endpoints[i].refs && endpoints[i].port==scoped.sin6_port && !memcmp(&normalized,&endpoints[i].address,16)) { scope=endpoints[i].scope; break; }
            pthread_mutex_unlock(&endpoint_lock);
            if(scope) {
#ifdef AQ_SOCKET_DIAGNOSTICS
                fprintf(stderr,"AirDrop connectx scope %u -> %u, interface %u\n",scoped.sin6_scope_id,scope,interface);
#endif
                scoped.sin6_addr=normalized; scoped.sin6_scope_id=scope;
                return original_connectx(fd,source,sourceLength,(const struct sockaddr *)&scoped,sizeof(scoped),scope,association,connection);
            }
        }
    }
    return original_connectx(fd,source,sourceLength,destination,length,interface,association,connection);
}
