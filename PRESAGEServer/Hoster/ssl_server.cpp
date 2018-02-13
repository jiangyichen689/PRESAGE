#include"ssl_server.h"

#include <winsock2.h>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

//get SSL_CTX and check the certificate and private key.
SSL_CTX * initilizeSSL(char * certificate_file, char * privateKey_file){
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method());

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}

	if (SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, privateKey_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	/* check the private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(5);
	}

	return ctx;
}

SSL_CTX * initilizeSSL1(char * certificate_file, char * privateKey_file){
	SSL_library_init();

	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	SSL_CTX * ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	if (SSL_CTX_use_certificate_file(ctx, certificate_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, privateKey_file, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* check the private key */
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	return ctx;
}

SSL* acceptSSL(int new_socketfd, SSL_CTX* ctx){
	  SSL* ssl = SSL_new (ctx);                           CHK_NULL(ssl);
	  SSL_set_fd (ssl, new_socketfd);
	  int err = SSL_accept (ssl);                        CHK_SSL(err);

	  return ssl;
	/* construct a new SSL based on ctx*/
	//SSL* ssl = SSL_new(ctx);
	/* add the client socket to SSL */
	//SSL_set_fd(ssl, new_socketfd);

	//if (SSL_accept(ssl) == -1) {
	//	return NULL;
	//}else{
	//	return ssl;
	//}
	
}

void disconnectSSL(SSL* ssl){
	SSL_shutdown(ssl);
	SSL_free(ssl);
}

void freeCTX(SSL_CTX *ctx){
	SSL_CTX_free(ctx);
}