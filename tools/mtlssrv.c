// mtlssrv -- a local TLS server that demands a client certificate, so the engine's
// client-certificate path can be tested against something that reports what it received.
//
// It exists for one question the public internet cannot be asked reliably: did the client
// actually send its certificate, or did it send an empty Certificate message? A client that
// sends nothing still completes the handshake under TLS 1.3 -- the client finishes before the
// server has said anything -- so only the server knows, and it says so on stdout:
//
//   CLIENT_CERT <subject>     the client presented a certificate
//   NO_CLIENT_CERT            it presented none, or the handshake failed
//
// Built against the vendored OpenSSL, not the system one, which is 0.9.8 and speaks no
// TLS 1.2. Its own security level is 0 so that the *server* never becomes the reason a small
// client key is refused -- the point of the test is what the client does with it.
//
//   cc -o mtlssrv tools/mtlssrv.c -Ibuild/openssl/include \
//      build/openssl/lib/libssl.a build/openssl/lib/libcrypto.a
//
//   ./mtlssrv <port> <server.crt> <server.key> <ca.crt>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Every client certificate is accepted, including one signed by nobody we know. Whether the
// certificate is any good is not what this server is for; whether one arrived at all is.
static int accept_any(int ok, X509_STORE_CTX *ctx) { (void)ok; (void)ctx; return 1; }

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: mtlssrv <port> <cert> <key> <cacert>\n"); return 2; }
    int port = atoi(argv[1]);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 2; }
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 2;
    }
    SSL_CTX_load_verify_locations(ctx, argv[4], NULL);
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(argv[4]));
    // FAIL_IF_NO_PEER_CERT is what turns "sent nothing" into a handshake the server rejects,
    // which is the behaviour of the services this path exists for.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, accept_any);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 4)) { perror("bind/listen"); return 2; }

    // Announced once the port is accepting, so a driver can wait for this line instead of
    // sleeping and hoping.
    printf("LISTENING %d\n", port);
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { perror("accept"); return 2; }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    int rc = SSL_accept(ssl);

    X509 *peer = rc == 1 ? SSL_get1_peer_certificate(ssl) : NULL;
    if (peer) {
        char name[256] = "?";
        X509_NAME_oneline(X509_get_subject_name(peer), name, sizeof name);
        printf("CLIENT_CERT %s\n", name);
        X509_free(peer);
    } else {
        printf("NO_CLIENT_CERT\n");
        if (rc != 1) ERR_print_errors_fp(stderr);
    }
    fflush(stdout);

    SSL_free(ssl);
    close(fd);
    close(ls);
    SSL_CTX_free(ctx);
    return peer != NULL ? 0 : 1;
}
