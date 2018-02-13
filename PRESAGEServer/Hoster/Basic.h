#include <tchar.h>
//#include "Distributed_Secure_GWAS_enclave_u.h"
#include "PresageEnclave_u.h"
#include "Socket.h"
#include <sstream>

//#define ENCLAVE_FILE _T("Distributed_Secure_GWAS_enclave.signed.dll") 
#define ENCLAVE_FILE _T("PresageEnclave.signed.dll") 
#define PROFILE_DEEZ

int attestation(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, sgx_status_t status, Socket *S, int socket_fd, int client_id);

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY( FILE *file, void *mem, uint32_t len);