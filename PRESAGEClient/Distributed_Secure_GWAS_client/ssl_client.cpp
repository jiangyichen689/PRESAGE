#include"ssl_client.h"

int verifyCertificate(char* cert_file, char * chain_file);

// Get server's certificate (note: beware of dynamic allocation) - opt
void verifyCertificate(SSL * ssl){
	char*    str;
	X509* server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
	if(VERBOSE){
		printf ("Server certificate:\n");
	}

	str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
	CHK_NULL(str);
	if(VERBOSE){
		printf ("\t subject: %s\n", str);
	}
	OPENSSL_free (str);

	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
	CHK_NULL(str);
	if(VERBOSE){
		printf ("\t issuer: %s\n", str);
	}
	OPENSSL_free (str);

	//verify certificate
	
	//printf("verify: %d\n", verifyCertificate("enclave_server.cert.pem", "ca-chain.cert.pem"));
	X509_free (server_cert);
}

//get SSL_CTX.
SSL_CTX * initilizeSSL(){
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());		CHK_NULL(ctx);

	return ctx;
}

//establish SSL
SSL* establishSSL(int sd, SSL_CTX* ctx){
	SSL* ssl = SSL_new (ctx);							CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	int err = SSL_connect (ssl);						CHK_SSL(err);

	if(SSL_get_verify_result(ssl) != X509_V_OK){
		if(VERBOSE){
			printf("fail to verify server's certificate!\n");
		}
		exit(1);
	}else{
		if(VERBOSE){
			printf("Successfully verify server's certificate!\n");
		}
	}

	if(VERBOSE){
		printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
		//verifyCertificate(ssl);
	}

	return ssl;
}

//destroy SSL
void disconnectSSL(SSL* ssl){
	SSL_shutdown (ssl);
	SSL_free(ssl);
}

//free ctx
void freeCTX(SSL_CTX * ctx){
	SSL_CTX_free(ctx);
}

X509 *loadCert(char* filename)
{
	X509* cert = X509_new();
    BIO* bio_cert = BIO_new_file(filename, "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
	return cert;
}

void loadToStore(char* file, X509_STORE *&store)
{
	X509 *cert = loadCert(file);
	if (cert != NULL)
	{
		X509_STORE_add_cert(store, cert);
	}
	else
	{
		printf("Can not load certificate %s\n", file);
	}
}

int verifyCertificate(char* filename, char * chain_file)
{
	X509* cert = loadCert(filename);
	int status = 0;
	X509_STORE *store = X509_STORE_new();

	loadToStore(chain_file, store);

	// Create the context to verify the certificate. 
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();

	// Initial the store to verify the certificate.
	X509_STORE_CTX_init(ctx, store, cert, NULL);

	status = X509_verify_cert(ctx);

	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	ctx = NULL;
	store = NULL;

	return status;
}
