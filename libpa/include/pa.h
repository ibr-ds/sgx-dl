#ifndef ENCLAVE_DYNAMIC_FUNCTIONS_H
#define ENCLAVE_DYNAMIC_FUNCTIONS_H

#include "pa_error.h"
#include <stdint.h>
#include <sgx_tcrypto.h>
#include "dl_patch.h"

#define __DL_ASLR 1
#define IBASLR_LOWER_BOUND 500
#define IBASLR_UPPER_BOUND 1000

#define MAX_SHUFFLING_STATE 100000

#ifndef PA_MAX_FCT_NAME_LENGTH
#define PA_MAX_FCT_NAME_LENGTH 64
#endif

#ifdef __cplusplus
extern "C" {
#endif

dl_status_t dl_add_enclave_fct(char* enclave_path, sgx_sha256_hash_t *symhash, sgx_sha256_hash_t *strhash);

typedef uint64_t dl_fct_id_t;
typedef uint64_t dl_file_handle_t;

typedef struct
{
	char *name;
	dl_file_handle_t file_handle;
} dl_fct_t;

typedef struct
{
	sgx_sha256_hash_t hash;
} dl_measurement_t;

#define DL_EMPTY_HANDLE (0)

dl_status_t dl_add_file(void *file_ptr, dl_file_handle_t *file_handle);

dl_status_t dl_add_fct(const char* fct_name, dl_file_handle_t file_handle);

dl_status_t dl_add_fct_arr(dl_fct_t *fcts, size_t num_fcts);

dl_status_t dl_del_fct(const char* fct_name);

dl_status_t dl_destroy(void);

dl_status_t dl_load_fct(const char* fct_name);

dl_status_t dl_call_ex(const char* fct_name, void** retval, void* args);

dl_status_t dl_call(const char* fct_name, void* args);

dl_status_t dl_start_call(const char* fct_name, void **fct_ptr);

dl_status_t dl_end_call(const char* fct_name);

dl_status_t dl_unload_fct(const char* fct_name);

dl_status_t dl_update_fct(dl_file_handle_t hndl, const char* fct_name, void* file_ptr);

dl_status_t dl_check_consistency();

dl_status_t dl_measure(dl_measurement_t *msr);

dl_status_t dl_patch(void *file_ptr, dl_patch_desc_t *desc);

char *dl_get_error();

#ifdef __cplusplus
}
#endif

#endif //ENCLAVE_DYNAMIC_FUNCTIONS_H
