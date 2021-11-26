//
// Created by joshua on 14.10.18.
//

#define FALSE 0
#define TRUE 1
#define TOKEN_FILE_TYPE ".token"

#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include "enclave_u.h"
//#include "elfparser.h"
#include "test_structs.h"
//////////////////////////////////////////
#include <time.h>
#include <pthread.h>
//////////////////////////////////////////

void *read_file(char *file_name, int *file_size)
{
	FILE *fp;
	size_t read;
	printf("[Info] Try to open %s.\n", file_name);
	fp = fopen(file_name, "rb");
	if (fp == NULL)
	{
		printf("[Error] Cant open %s.\n", file_name);
		return NULL;
	}
	fseek(fp, 0L, SEEK_END);
	*file_size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	printf("[Info] File-size: %d (Byte).\n", *file_size);
	char *file = (char *) malloc(sizeof(char) * (*file_size));
	read = fread(file, 1, *file_size, fp);
	if (read != *file_size)
	{
		printf("[Error] Read error.\n");
		return NULL;
	}
	return file;
}

void free_file(void *ptr)
{
	printf("[Info] free() %p.\n", ptr);
	free(ptr);
}

sgx_enclave_id_t enclave_1_id;

int initiate_enclave(const char *enclave_path)
{
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	ret = sgx_create_enclave(enclave_path, 1, &token, &updated, &enclave_1_id, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("Can't create enclave: 0x%x\n", ret);
		return -1;
	}

	return TRUE;
}

//////////////////////////////////////////
#define FILE_MEASUREMENT "../Evaluation/Result_pa_call_ex_LOADED_SC_50K.txt"
clock_t clock_0;
struct timespec tp_start, tp_stop, tp_diff;
FILE *fp = NULL;

struct timespec diff(struct timespec _start, struct timespec _end)
{
	struct timespec result = {};
	if ((_end.tv_nsec - _start.tv_nsec) < 0)
	{
		result.tv_sec = _end.tv_sec - _start.tv_sec - 1;
		result.tv_nsec = 1000000000 + _end.tv_nsec - _start.tv_nsec;
	}
	else
	{
		result.tv_sec = _end.tv_sec - _start.tv_sec;
		result.tv_nsec = _end.tv_nsec - _start.tv_nsec;
	}
	return result;
}

void measurement_start_timer(void)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &tp_start);
}

void measurement_stop_timer(void)
{
	clock_gettime(CLOCK_MONOTONIC_RAW, &tp_stop);
	tp_diff = diff(tp_start, tp_stop);
	if (fp == NULL)
	{
		fp = fopen(FILE_MEASUREMENT, "w");
	}
	fprintf(fp, "%lu.%09lu\n", tp_diff.tv_sec, tp_diff.tv_nsec);
	//printf("Time %u.%09lu",tp_diff.tv_sec,tp_diff.tv_nsec);
}

void _measurement()
{
	measurement(enclave_1_id);
	printf("Start: %lu.%09lu Stop: %lu.%09lu\\ Diff: %lu.%09lu\n", tp_start.tv_sec, tp_start.tv_nsec, tp_stop.tv_sec, tp_stop.tv_nsec, tp_diff.tv_sec, tp_diff.tv_nsec);
	fclose(fp);
}
//////////////////////////////////////////

void *_thread_test(void *id)
{
	printf("Thread created.\n");
	for (int i = 0; i < 100000; i++)
	{
		thread_test(enclave_1_id);
	}
	printf("Thread finished.\n");
	return NULL;
}

extern "C" void ocall_print_string(const char *s)
{
	std::cout << s;
}

//////////////////////////////////////////
int main(int argc, char **argv)
{
#ifdef SIMMODE
	if(initiate_enclave("libpatestenclavesim.signed.so") == FALSE){
#else
	if (initiate_enclave("libpatestenclave.signed.so") == FALSE)
	{
#endif
		printf("[Error] Cant initiate Enclave.\n");
	}
	else
	{
		printf("[Info] Enclave created successfully with Enclave_ID: %lu.\n", enclave_1_id);
	}
	//Dev Tests
	//measurement_start_timer();
	init(enclave_1_id);
	//Thread
	/*pthread_t thread_1,thread_2,thread_3;
	int x = 1, y = 2, z = 3;
	Enclave_1_thread_init(enclave_1_id);
	pthread_create(&thread_1,NULL,thread_test,&x);
	pthread_create(&thread_2,NULL,thread_test,&y);
	pthread_create(&thread_3,NULL,thread_test,&z);
	//_thread_test(&x);
	pthread_join(thread_1,NULL);
	pthread_join(thread_2,NULL);
	pthread_join(thread_3,NULL);*/
	//measurement_stop_timer();
	//Measurement
	//_measurement();
	return 0;
}
