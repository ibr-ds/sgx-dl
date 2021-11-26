#include <iostream>
#include "sgx_urts.h"

#include "enclave_u.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef SIMMODE
#define ENCLAVE_PATCH_FILENAME "libexampleenclavesim.signed.so"
#define ENCLAVE_BASELINE1_FILENAME "libexamplebaseline1enclavesim.signed.so"
#define ENCLAVE_BASELINE2_FILENAME "libexamplebaseline2enclavesim.signed.so"
#else
#define ENCLAVE_PATCH_FILENAME "libexampleenclave.signed.so"
#define ENCLAVE_PATCHIB_FILENAME "libexampleenclavebenchibaslr.signed.so"
#define ENCLAVE_BASELINE1_FILENAME "libexamplebaseline1enclave.signed.so"
#define ENCLAVE_BASELINE2_FILENAME "libexamplebaseline2enclave.signed.so"
#endif

sgx_enclave_id_t eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
		{
				SGX_ERROR_UNEXPECTED,
				"Unexpected error occurred.",
				NULL
		},
		{
				SGX_ERROR_INVALID_PARAMETER,
				"Invalid parameter.",
				NULL
		},
		{
				SGX_ERROR_OUT_OF_MEMORY,
				"Out of memory.",
				NULL
		},
		{
				SGX_ERROR_ENCLAVE_LOST,
				"Power transition occurred.",
				"Please refer to the sample \"PowerTransition\" for details."
		},
		{
				SGX_ERROR_INVALID_ENCLAVE,
				"Invalid enclave image.",
				NULL
		},
		{
				SGX_ERROR_INVALID_ENCLAVE_ID,
				"Invalid enclave identification.",
				NULL
		},
		{
				SGX_ERROR_INVALID_SIGNATURE,
				"Invalid enclave signature.",
				NULL
		},
		{
				SGX_ERROR_OUT_OF_EPC,
				"Out of EPC memory.",
				NULL
		},
		{
				SGX_ERROR_NO_DEVICE,
				"Invalid SGX device.",
				"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
		},
		{
				SGX_ERROR_MEMORY_MAP_CONFLICT,
				"Memory map conflicted.",
				NULL
		},
		{
				SGX_ERROR_INVALID_METADATA,
				"Invalid enclave metadata.",
				NULL
		},
		{
				SGX_ERROR_DEVICE_BUSY,
				"SGX device was busy.",
				NULL
		},
		{
				SGX_ERROR_INVALID_VERSION,
				"Enclave version was invalid.",
				NULL
		},
		{
				SGX_ERROR_INVALID_ATTRIBUTE,
				"Enclave was not authorized.",
				NULL
		},
		{
				SGX_ERROR_ENCLAVE_FILE_ACCESS,
				"Can't open enclave file.",
				NULL
		},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if(ret == sgx_errlist[idx].err) {
			if(NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}

int initialize_enclave(char *filename)
{
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(filename, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		return -1;
	}

	return 0;
}

static volatile int do_bench = 0;
static volatile int abort_measure = 0;
volatile uint64_t counter = 0;
uint64_t RATE = 100000;
uint64_t BEFORE_PATCH = 50000;
uint64_t AFTER_PATCH = 50000;

static inline uint64_t rdtscp( uint32_t & aux )
{
	uint64_t rax,rdx;
	asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
	return (rdx << 32) + rax;
}

typedef struct {
	uint64_t tsc;
	uint64_t diff;
} measurement_t;

measurement_t *array;
#define ARRAY_SIZE (1000000)
uint64_t cur_elem = 0;
uint32_t a;


static inline void add_measurement(uint64_t diff)
{
	array[cur_elem].diff = diff;
	array[cur_elem].tsc = rdtscp(a);
	++cur_elem;
	if (cur_elem >= ARRAY_SIZE)
		cur_elem = 0;
}

// "print" to array

void *measure_thread(void *args)
{
	printf("# RATE: %lu µs\n", RATE);
	uint64_t last = 0, diff, cur;
	uint64_t next = 0;
	while(do_bench == 0)
	{
		__asm__("pause");
	}
	while(abort_measure == 0)
	{
		next = rdtscp(a) + RATE;
		cur = counter;
		diff = cur - last;
		last = cur;
		add_measurement(diff);
		while(rdtscp(a) < next)
		{
			__asm__("pause");
		}
	}

	return nullptr;
}

uint64_t WORKER_THREADS = 1;
pthread_barrier_t worker_barrier;

void *worker_thread(void *args)
{
	pthread_barrier_wait(&worker_barrier);
	while(do_bench == 0)
	{
		__asm__("pause");
	}

	sgx_status_t ret = ecall_bench(eid);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "SGX error: 0x%x\n", ret);
		exit(-1);
	}

	return nullptr;
}

static void test()
{
	initialize_enclave(const_cast<char *>(ENCLAVE_PATCH_FILENAME));
	ecall_test(eid, "patch.c.o");
	//sgx_destroy_enclave(eid);
	//initialize_enclave(const_cast<char *>(ENCLAVE_PATCH_FILENAME));
	//ecall_test(eid, "patch_rust.c.o");
}

static void test2()
{
	initialize_enclave(const_cast<char *>(ENCLAVE_PATCH_FILENAME));
	ecall_test2(eid, "patch.c.o");
	//sgx_destroy_enclave(eid);
	//initialize_enclave(const_cast<char *>(ENCLAVE_PATCH_FILENAME));
	//ecall_test(eid, "patch_rust.c.o");
}

static void print_array()
{
	// print array
	uint64_t end = cur_elem - 1;
	if (end < 0)
	{
		end = ARRAY_SIZE - 1;
	}
	uint64_t prev_elem = end;
	uint64_t start_tsc = 0;
	while (cur_elem != end)
	{
		if (array[cur_elem].tsc != 0)
		{
			if (start_tsc == 0)
				start_tsc = array[cur_elem].tsc;

			printf("%lu, %lu, %lu\n", array[cur_elem].tsc - start_tsc, array[cur_elem].diff, array[cur_elem].tsc - array[prev_elem].tsc);
		}
		++cur_elem;
		++prev_elem;
		if (cur_elem >= ARRAY_SIZE)
		{
			cur_elem = 0;
		}
		if (prev_elem >= ARRAY_SIZE)
		{
			prev_elem = 0;
		}
	}
}

static void patch(char *filename)
{
	initialize_enclave(filename);

	//return 0;
	pthread_t measure, worker[WORKER_THREADS];
	pthread_create(&measure, nullptr, measure_thread, nullptr);
	pthread_barrier_init(&worker_barrier, nullptr, WORKER_THREADS + 1);
	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		pthread_create(worker+i, nullptr, worker_thread, nullptr);
	}
	pthread_barrier_wait(&worker_barrier);

	counter = 0;
	array = (measurement_t *)calloc(ARRAY_SIZE, sizeof(measurement_t));
	ecall_start_bench(eid, (uint64_t *)&counter);
	do_bench = 1;

	//getchar();
	//do_bench = 2;
	usleep(BEFORE_PATCH);
	ecall_patch(eid);
	usleep(AFTER_PATCH);
	//do_bench = 3;
	//usleep(1000);
	//getchar();
//	do_bench = 0;
	ecall_stop_bench(eid);

	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		pthread_join(worker[i], nullptr);
	}
	abort_measure = 1;
	pthread_join(measure, nullptr);

	print_array();
}

static void baseline()
{
	sgx_status_t ret = SGX_SUCCESS;
	initialize_enclave(const_cast<char *>(ENCLAVE_BASELINE1_FILENAME));

	//return 0;
	pthread_t measure, worker[WORKER_THREADS];
	pthread_create(&measure, nullptr, measure_thread, nullptr);
	pthread_barrier_init(&worker_barrier, nullptr, WORKER_THREADS + 1);
	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		fprintf(stderr, "Creating worker %d\n", i);
		pthread_create(worker+i, nullptr, worker_thread, nullptr);
	}
	pthread_barrier_wait(&worker_barrier);

	fprintf(stderr, "Starting benchmark \n");
	counter = 0;
	array = (measurement_t *)calloc(ARRAY_SIZE, sizeof(measurement_t));
	ret = ecall_start_bench(eid, (uint64_t *)&counter);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "SGX error: 0x%x\n", ret);
		exit(-1);
	}
	do_bench = 1;

	//getchar();
	//do_bench = 2;
	usleep(BEFORE_PATCH);

	ret = ecall_stop_bench(eid);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "SGX error: 0x%x\n", ret);
		exit(-1);
	}

	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		fprintf(stderr, "Joining worker %d\n", i);
		pthread_join(worker[i], nullptr);
	}
	sgx_destroy_enclave(eid);

	do_bench = 0;
	pthread_barrier_init(&worker_barrier, nullptr, WORKER_THREADS + 1);
	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		fprintf(stderr, "Creating worker %d\n", i);
		pthread_create(worker+i, nullptr, worker_thread, nullptr);
	}
	initialize_enclave(const_cast<char *>(ENCLAVE_BASELINE2_FILENAME));
	pthread_barrier_wait(&worker_barrier);
	fprintf(stderr, "Re-Starting benchmark \n");
	ret = ecall_start_bench(eid, (uint64_t *)&counter);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "SGX error: 0x%x\n", ret);
		exit(-1);
	}
	do_bench = 1;

	usleep(AFTER_PATCH);
	//do_bench = 3;
	//usleep(1000);
	//getchar();
	ret = ecall_stop_bench(eid);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "SGX error: 0x%x\n", ret);
		exit(-1);
	}

	for (int i = 0; i < WORKER_THREADS; ++i)
	{
		fprintf(stderr, "Joining worker %d\n", i);
		pthread_join(worker[i], nullptr);
	}
	abort_measure = 1;
	fprintf(stderr, "Joining measure \n");
	pthread_join(measure, nullptr);

	print_array();
}

#include <time.h>

void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result->tv_sec = stop->tv_sec - start->tv_sec - 1;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result->tv_sec = stop->tv_sec - start->tv_sec;
		result->tv_nsec = stop->tv_nsec - start->tv_nsec;
	}
}

int main(int argc, char **argv)
{
#ifdef BENCHMARK
	sgx_status_t ret = SGX_SUCCESS;
	int res = 0;
	if (initialize_enclave(const_cast<char *>("libexampleenclavebench.signed.so")) != 0)
	{
		fprintf(stderr, "error init enclave \n");
		return -1;
	}

	struct timespec start, end, diff;

	ecall_init_bench(eid, &ret);
	if (ret != SGX_SUCCESS)
	{
		fprintf(stderr, "error init bench 0x%x\n", ret);
		return -1;
	}

	printf("ms add, cycles add, ms load, cycles load\n");

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	ecall_add_bench(eid, &res);
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	if (res != 0)
	{
		fprintf(stderr, "error adding");
		return -1;
	}

	timespec_diff(&start, &end, &diff);
	auto time = static_cast<uint64_t>(diff.tv_sec * 1000000000 + diff.tv_nsec);

	printf("%lu, ", time);
	fflush(stdout);

	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	ecall_load_bench(eid, &res);
	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	if (res != 0)
	{
		fprintf(stderr, "error loading");
		return -1;
	}

	uint64_t cycles[4];
	ecall_get_cycles(eid, (uint64_t *)&cycles);

	printf("%lu, ", cycles[1]-cycles[0]);

	timespec_diff(&start, &end, &diff);
	time = static_cast<uint64_t>(diff.tv_sec * 1000000000 + diff.tv_nsec);

	printf("%lu, ", time);
	printf("%lu\n", cycles[3]-cycles[2]);
#else
	errno = 0;
	if (argc > 1)
	{
		if (!strncmp("testrs", argv[1], 6))
		{
			test2();
			return 0;
		}

		if (!strncmp("test", argv[1], 4))
		{
			test();
			return 0;
		}

		if (argc > 2)
		{
			RATE = strtoul(argv[2], nullptr, 10);
			if (errno != 0)
			{
				fprintf(stderr, "can't convert '%s' to uint64_t\n", argv[2]);
				return 1;
			}
		}

		if (argc > 3)
		{
			WORKER_THREADS = strtoul(argv[3], nullptr, 10);
			if (errno != 0)
			{
				fprintf(stderr, "can't convert '%s' to uint64_t\n", argv[3]);
				return 1;
			}
			if (WORKER_THREADS > 20)
			{
				fprintf(stderr, "to many threads!!! max 20\n");
				return 1;
			}
		}

		if (!strncmp("patchib", argv[1], 7))
		{
			patch(ENCLAVE_PATCHIB_FILENAME);
			return 0;
		}

		if (!strncmp("patch", argv[1], 5))
		{
			patch(ENCLAVE_PATCH_FILENAME);
			return 0;
		}

		if (!strncmp("base", argv[1], 4))
		{
			baseline();
			return 0;
		}
	}

	printf("Usage: %s <mode> [samplerate]\n", argv[0]);
	printf("mode: test\n" \
	       "      testrs\n" \
	       "      patch\n" \
	       "      patchib\n" \
	       "      base\n");
#endif
	return 0;
}

extern "C" void ocall_print_string(const char *s)
{
	std::cout << s;
}

extern "C" void ocall_map_file(const char *path, void **addr, size_t *size)
{
	int fd = open(path, O_RDONLY);
	struct stat sb = {};
	fstat(fd, &sb);
	*size = (size_t)sb.st_size;

	*addr = mmap(nullptr, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*addr == nullptr)
	{
		std::cerr << "mmap error" << std::endl;
		return;
	}
}

extern "C" void ocall_munmap(void *addr, size_t size)
{
	munmap(addr, size);
}
