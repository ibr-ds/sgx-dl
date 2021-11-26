#include <stdlib.h>
#include <sys/mman.h>

#include <sgx.h>
#include <sgx_eid.h>
#include <pthread.h>

sgx_status_t ecall_dl_start_shuffling(sgx_enclave_id_t);

void *ocall_malloc(size_t size)
{
	void *addr = malloc(size);
	if (addr == NULL)
		abort();
	return addr;
}

void ocall_free(void *addr)
{
	free(addr);
}

static void* shuffle_thread_func(void* p)
{
	sgx_enclave_id_t eid = (sgx_enclave_id_t)p;
	sgx_status_t status = ecall_dl_start_shuffling(eid);
	return NULL;
}

int dl_create_shuffling_thread(sgx_enclave_id_t eid, pthread_t *thread)
{
	int res = pthread_create(thread, NULL, shuffle_thread_func, (void *)eid);
	return res;
}

