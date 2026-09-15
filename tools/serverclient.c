#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc,char **argv) {
    if(argc!=4 && argc!=5) return 2;
    SSL_CTX *context=SSL_CTX_new(TLS_client_method()); SSL *ssl=NULL; int fd=-1,result=1;
    if(!context || !SSL_CTX_load_verify_locations(context,argv[2],NULL)) goto done;
    SSL_CTX_set_verify(context,SSL_VERIFY_PEER,NULL);
    if(argc==5 && (!SSL_CTX_use_certificate_file(context,argv[2],SSL_FILETYPE_PEM) || !SSL_CTX_use_PrivateKey_file(context,argv[4],SSL_FILETYPE_PEM))) goto done;

    int version=atoi(argv[3])==13 ? TLS1_3_VERSION : TLS1_2_VERSION;
    SSL_CTX_set_min_proto_version(context,version); SSL_CTX_set_max_proto_version(context,version);
    SSL_CTX_set_cipher_list(context,"ECDHE-RSA-AES128-GCM-SHA256");
    fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) goto done;
    struct timeval timeout={10,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)); setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int one=1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct sockaddr_in address; memset(&address,0,sizeof(address)); address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(atoi(argv[1]));
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))) goto done;
    ssl=SSL_new(context); if(!ssl || SSL_set_fd(ssl,fd)!=1 || SSL_set1_host(ssl,"localhost")!=1 || SSL_connect(ssl)!=1) goto done;
    if(SSL_get_verify_result(ssl)!=X509_V_OK || SSL_write(ssl,"ping",4)!=4) goto done;
    char bytes[4]; if(SSL_read(ssl,bytes,4)!=4 || memcmp(bytes,"pong",4)) goto done;
    printf("PASS: %s %s, certificate verified, bytes match\n",SSL_get_version(ssl),SSL_get_cipher(ssl)); result=0;
done:
    if(result) ERR_print_errors_fp(stderr);
    if(ssl) { SSL_shutdown(ssl); SSL_free(ssl); } if(fd>=0) close(fd); SSL_CTX_free(context); return result;
}
