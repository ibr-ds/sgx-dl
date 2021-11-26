#include "enclave_t.h"
#include "pa.h"
#include "loadable.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

static void print_msr(dl_measurement_t *msr)
{
	printf("MRDL: ");
	for (size_t i = 0; i < sizeof(sgx_sha256_hash_t); ++i)
	{
			printf("%02x", msr->hash[i]);
	}
	printf("\n");
}

/*
static void add_patch_funcs(char *file)
{
	void *addr = nullptr;
	size_t size = 0;
	sgx_status_t sres = ocall_map_file(file, &addr, &size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: %d\n", sres);
		return;
	}
	if (addr == nullptr)
	{
		printf("got no valid address back\n");
		return;
	}

	dl_file_handle_t handle = DL_EMPTY_HANDLE;
	dl_status_t res = dl_add_file(addr, &handle);
	if (res != DL_SUCCESS)
	{
		printf("[add file1] PA error: 0x%x\n", res);
		return;
	}

	sres = ocall_munmap(addr, size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: 0x%x\n", sres);
		return;
	}
}
//*/

static void add_funcs()
{
	void *addr = nullptr, *addr_2 = nullptr;
	size_t size = 0;

	// Map ELF files

	sgx_status_t sres = ocall_map_file("add.c.o", &addr, &size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: %d\n", sres);
		return;
	}

	if (addr == nullptr)
	{
		printf("got no valid address back\n");
		return;
	}

	sres = ocall_map_file("loadable.c.o", &addr_2, &size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: %d\n", sres);
		return;
	}

	if (addr_2 == nullptr)
	{
		printf("got no valid address back\n");
		return;
	}

	// Register with lib

	dl_file_handle_t handle = DL_EMPTY_HANDLE;
	dl_status_t res = dl_add_file(addr, &handle);
	if (res != DL_SUCCESS)
	{
		printf("[add file1] PA error: 0x%x\n", res);
		return;
	}

	dl_file_handle_t handle_2 = DL_EMPTY_HANDLE;
	res = dl_add_file(addr_2, &handle_2);
	if (res != DL_SUCCESS)
	{
		printf("[add file2] PA error: 0x%x\n", res);
		return;
	}

	// Add functions

	dl_fct_t fcts[4];
	fcts[0].name = (char *)"bla";
	fcts[0].file_handle = handle_2;
	fcts[1].name = (char *)"getCounter";
	fcts[1].file_handle = handle_2;
	fcts[2].name = (char *)"mul";
	fcts[2].file_handle = handle_2;
	fcts[3].name = (char *)"add";
	fcts[3].file_handle = handle;
	fcts[4].name = (char *)"other_signature";
	fcts[4].file_handle = handle_2;

	res = dl_add_fct_arr(fcts, 5);
	if (res != DL_SUCCESS)
	{
		printf("[add fcts] PA error: 0x%x\n", res);
		return;
	}

	/*
	res = pa_add_fct((char*)"add", handle);
	if (res != DL_SUCCESS)
	{
		printf("[add add] PA error: 0x%x\n", res);
		return;
	}

	res = pa_add_fct((char*)"mul", handle_2);
	if (res != DL_SUCCESS)
	{
		printf("[add mul] PA error: 0x%x\n", res);
		return;
	}

	res = pa_add_fct((char*)"bla", handle_2);
	if (res != DL_SUCCESS)
	{
		printf("[add bla] PA error: 0x%x\n", res);
		return;
	}

	res = pa_add_fct((char*)"getCounter", handle_2);
	if (res != DL_SUCCESS)
	{
		printf("[add getCounter] PA error: 0x%x\n", res);
		return;
	}
	//*/

	// Unmap ELF files

	sres = ocall_munmap(addr, size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: 0x%x\n", sres);
		return;
	}

	sres = ocall_munmap(addr_2, size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: 0x%x\n", sres);
		return;
	}

	sgx_sha256_hash_t symhash = {0x02, 0x0e, 0x6c, 0x3a, 0xc8, 0xaf, 0x74, 0x74, 0x35, 0xe6, 0xe2, 0x39, 0x6a, 0x5c, 0x40, 0xec, 0xa2, 0x1d, 0xd4, 0xe1, 0xbe, 0x27, 0x65, 0x61, 0xbc, 0xf5, 0x3e, 0xa1, 0x7a, 0xe1, 0xa2, 0xc7};
	sgx_sha256_hash_t strhash = {0x98, 0x1e, 0x10, 0x67, 0xab, 0x0e, 0xfd, 0xd9, 0x79, 0x00, 0xc2, 0xa0, 0xf6, 0xbe, 0xcc, 0x70, 0xdb, 0x77, 0xf4, 0x69, 0x91, 0xc7, 0xdf, 0xbb, 0xdd, 0x17, 0x34, 0x81, 0x74, 0x2a, 0x63, 0x89};	//{0x96, 0xa6, 0xbe, 0x7d, 0x75, 0xc4, 0x04, 0xcc, 0xfb, 0xf5, 0x25, 0xa8, 0x83, 0x48, 0xf6, 0x61, 0xb4, 0xdc, 0xd7, 0x95, 0xf4, 0x90, 0x7b, 0x14, 0x92, 0x02, 0xc3, 0x5a, 0x98, 0xe3, 0xdb, 0x43};
	res = dl_add_enclave_fct((char *)"libexampleenclave.signed.so", &symhash, &strhash);
	if (res != DL_SUCCESS)
	{
		printf("[add enclave] PA error: 0x%x\n", res);
		if (res == PA_SYMTAB_HASH_MISMATCH || res == PA_STRTAB_HASH_MISMATCH)
		{
			printf("%s\n", dl_get_error());
		}
		return;
	}
}

static void load_funcs()
{
	dl_status_t res = dl_load_fct((char *) "bla");
	if (res != DL_SUCCESS)
	{
		printf("[load bla] PA error: 0x%x\n", res);
		return;
	}
	res = dl_load_fct((char *) "add");
	if (res != DL_SUCCESS)
	{
		printf("[load add] PA error: 0x%x\n", res);
		return;
	}
	res = dl_load_fct((char *) "mul");
	if (res != DL_SUCCESS)
	{
		printf("[load mul] PA error: 0x%x\n", res);
		return;
	}
	res = dl_load_fct((char *) "getCounter");
	if (res != DL_SUCCESS)
	{
		printf("[load getCounter] PA error: 0x%x\n", res);
		return;
	}
}

int temp_counter = 5;

static void call_funcs()
{
	args_add_t args = {};
	args.a = 5;
	args.b = 12;

	dl_status_t res = dl_call((char *) "add", &args);
	if (res != DL_SUCCESS)
	{
		printf("[call add] PA error: 0x%x\n", res);
		return;
	}
	printf("add result: %d\n", args.result);

	args.a = 5;
	args.b = 12;

	res = dl_call((char *) "mul", &args);
	if (res != DL_SUCCESS)
	{
		printf("[call mul] PA error: 0x%x\n", res);
		return;
	}

	printf("mul result: %d\n", args.result);

	args.a = 5;
	args.b = 12;

	res = dl_call((char *) "bla", &args);
	if (res != DL_SUCCESS)
	{
		printf("[call bla] PA error: 0x%x\n", res);
		return;
	}

	printf("bla result: %d\n", args.result);

	res = dl_call_ex((char *) "getCounter", (void **) &temp_counter, NULL);
	if (res != DL_SUCCESS)
	{
		printf("[call getCounter] PA error: 0x%x\n", res);
		return;
	}

	printf("counter: %d\n", temp_counter);

	int (*fct_ptr)(int, int, int);
	res = dl_start_call((char *) "other_signature", (void **)&fct_ptr);
	if (res != DL_SUCCESS)
	{
		printf("[call other_signature] PA error: 0x%x\n", res);
		return;
	}
	int x = fct_ptr(1, 4, 9);
	dl_end_call((char *) "other_signature");
	printf("other signature: %d\n", x);
}

#include "dl_patch.h"

static void update_func(char *patch_file, dl_patch_desc_t *desc)
{
	void *addr = nullptr;
	size_t size = 0;

	sgx_status_t sres = ocall_map_file(patch_file, &addr, &size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: %d\n", sres);
		return;
	}

	//dl_status_t res = dl_update_fct((char *) "add", addr);
	dl_status_t res = dl_patch(addr, desc);
	if (res != DL_SUCCESS)
	{
		printf("[update 3] PA error: 0x%x\n", res);
		return;
	}

	sres = ocall_munmap(addr, size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: 0x%x\n", sres);
		return;
	}
}


dl_patch_desc_t __dl_patch_1 = {
		.add_symbols = "add_helper",
		.pre_update_state_transfer_functions = NULL,
		.update_symbols = "add",
		.post_update_state_transfer_functions = NULL,
		.remove_symbols = NULL
};

dl_patch_desc_t __dl_patch_2 = {
		.add_symbols = NULL,
		.pre_update_state_transfer_functions = NULL,
		.update_symbols = "add",
		.post_update_state_transfer_functions = NULL,
		.remove_symbols = "add_helper"
};

extern "C" void ecall_test(char *patch_file)
{
	dl_measurement_t msr;
	dl_measure(&msr);
	print_msr(&msr);

	add_funcs();

	dl_measure(&msr);
	print_msr(&msr);

	/*
	load_funcs();

	dl_measure(&msr);
	print_msr(&msr);
	//*/
	call_funcs();

	dl_measure(&msr);
	print_msr(&msr);

	update_func((char *)"patch.c.o", &__dl_patch_1);

	dl_measure(&msr);
	print_msr(&msr);

	call_funcs();

	dl_measure(&msr);
	print_msr(&msr);

	update_func((char *)"patch.rs.o", &__dl_patch_2);

	dl_measure(&msr);
	print_msr(&msr);

	call_funcs();

	dl_measure(&msr);
	print_msr(&msr);
}

extern "C" void ecall_test2(char *patch_file)
{
	dl_measurement_t msr;
	dl_measure(&msr);
	print_msr(&msr);

	add_funcs();

	dl_measure(&msr);
	print_msr(&msr);

	/*
	load_funcs();

	dl_measure(&msr);
	print_msr(&msr);
	//*/
	call_funcs();

	dl_measure(&msr);
	print_msr(&msr);

	update_func((char *)"patch.rs.o", &__dl_patch_2);

	dl_measure(&msr);
	print_msr(&msr);

	call_funcs();

	dl_measure(&msr);
	print_msr(&msr);
}


static volatile int do_bench = 0;
volatile uint64_t *bench_counter = 0;

extern "C" void ecall_start_bench(uint64_t *ctr)
{
#ifndef BASELINE
	add_funcs();
	load_funcs();
#endif
	bench_counter = ctr;
	do_bench = 1;
}

extern "C" void ecall_stop_bench(void)
{
	do_bench = 2;
}

extern "C" void ecall_bench(void)
{
	args_add_t args = {.a = 5, .b = 12};

	while(do_bench == 0)
	{ __asm__("pause");}

	while(do_bench == 1)
	{
#ifdef BASELINE
		bla(&args);
		__sync_fetch_and_add(bench_counter, 1);
#else
		dl_status_t s = dl_call((char *)"bla", &args);
		if (s != DL_SUCCESS)
			abort();
		__sync_fetch_and_add(bench_counter, 1);
#endif
	}

	dl_check_consistency();
}

extern "C" void ecall_patch(void)
{
	update_func((char *)"patch.c.o", &__dl_patch_1);
}

void *bench_elf = nullptr;
size_t bench_elf_size = 0;
dl_file_handle_t bench_handle = DL_EMPTY_HANDLE;

extern "C" sgx_status_t ecall_init_bench()
{
	sgx_status_t sres = ocall_map_file("loadablebench/loadable.c.o", &bench_elf, &bench_elf_size);
	if (sres != SGX_SUCCESS)
	{
		printf("SGX error: 0x%x\n", sres);
		return sres;
	}
	dl_status_t res = dl_add_file(bench_elf, &bench_handle);
	if (res != DL_SUCCESS)
	{
		printf("PA error: 0x%x\n", res);
		abort();
	}
	return sres;
}

#define STRINGYFY(A) #A
#define TOSTR(A) STRINGYFY(A)
#define __FUNC(A) (char*)TOSTR(__func##A)

#define __FUNC2(A) \
__FUNC(A##0), \
__FUNC(A##1), \
__FUNC(A##2), \
__FUNC(A##3), \
__FUNC(A##4), \
__FUNC(A##5), \
__FUNC(A##6), \
__FUNC(A##7), \
__FUNC(A##8), \
__FUNC(A##9)

#define __FUNC3(A) \
__FUNC2(A##0), \
__FUNC2(A##1), \
__FUNC2(A##2), \
__FUNC2(A##3), \
__FUNC2(A##4), \
__FUNC2(A##5), \
__FUNC2(A##6), \
__FUNC2(A##7), \
__FUNC2(A##8), \
__FUNC2(A##9)

#define FUNC(A) \
__FUNC3(A##0), \
__FUNC3(A##1), \
__FUNC3(A##2), \
__FUNC3(A##3), \
__FUNC3(A##4), \
__FUNC3(A##5), \
__FUNC3(A##6), \
__FUNC3(A##7), \
__FUNC3(A##8), \
__FUNC3(A##9)

char *funcs[] = {FUNC(0),FUNC(1),FUNC(2),FUNC(3),FUNC(4),FUNC(5),FUNC(6),FUNC(7),FUNC(8),FUNC(9),nullptr};

static inline uint64_t rdtscp( uint32_t & aux )
{
	uint64_t rax,rdx;
	asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
	return (rdx << 32) + rax;
}

uint32_t a = 0;
uint64_t add_bench_start = 0, add_bench_stop = 0, load_bench_start = 0, load_bench_stop = 0;

uint64_t id = 0;
extern "C" int ecall_add_bench()
{
	char * cur = nullptr;
	dl_status_t ret = DL_SUCCESS;
	cur = funcs[id];
	add_bench_start = rdtscp(a);
	while (cur != nullptr)
	{
		ret = dl_add_fct(cur, bench_handle);
		if (ret != DL_SUCCESS)
		{
			printf("[add %s] error: 0x%x\n", cur, ret);
			return -1;
		}
		++id;
		cur = funcs[id];
	}
	add_bench_stop = rdtscp(a);

	return 0;
}

extern "C" int ecall_load_bench()
{
	dl_status_t ret = DL_SUCCESS;
	load_bench_start = rdtscp(a);
	for (uint64_t i = 0; i < id; ++i)
	{
		ret = dl_load_fct(funcs[i]);
		if (ret != DL_SUCCESS)
		{
			printf("[load %s] error: 0x%x\n", i, ret);
			return -1;
		}
	}
	load_bench_stop = rdtscp(a);

	return 0;
}

extern "C" void ecall_get_cycles(uint64_t *vals)
{
	vals[0] = add_bench_start;
	vals[1] = add_bench_stop;
	vals[2] = load_bench_start;
	vals[3] = load_bench_stop;
}
