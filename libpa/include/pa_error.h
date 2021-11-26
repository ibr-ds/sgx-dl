#ifndef ENCLAVE_PA_ERROR_H
#define ENCLAVE_PA_ERROR_H
#include <stdint.h>
#define DL_ERROR(X) ((uint32_t)(0x00000000)|(uint32_t)(X))

typedef enum _error
{
    DL_SUCCESS = DL_ERROR(0x0000),
    PA_CANT_OPEN_FILE = DL_ERROR(0x0001),
    PA_INVALID_FUNCTION_ID = DL_ERROR(0x0002),
    PA_PATH_TOO_LONG = DL_ERROR(0x0003),
    PA_INVALID_POINTER = DL_ERROR(0x0004),
    PA_FUNCTION_NOT_FOUND = DL_ERROR(0x0005),
    PA_UNKNOWN_ERROR = DL_ERROR(0x0006),
    PA_FUNCTION_NAME_TOO_LONG = DL_ERROR(0x0007),
    PA_EMPTY_FUNCTION_TABLE = DL_ERROR(0x0008),
    PA_NOT_AN_ELF = DL_ERROR(0x0009),
    PA_X86_ELF_NOT_SUPPORTED = DL_ERROR(0x000a),
    PA_ELF_MSB_NOT_SUPPORTED = DL_ERROR(0x000b),
    PA_FUNCTION_NOT_LOADED = DL_ERROR(0x000c),
    PA_INVALID_FILE_ID = DL_ERROR(0x000d),
    PA_FUNCTION_ALREADY_EXISTS = DL_ERROR(0x000e),
    PA_FUNCTION_ALREADY_LOADED = DL_ERROR(0x000f),
    PA_UNSUPPORTED_SYMBOL_BINDING = DL_ERROR(0x0010),
    PA_UNSUPPORTED_SYMBOL_TYPE = DL_ERROR(0x0011),
    PA_SYMBOL_ALREADY_DEFINED = DL_ERROR(0x0012),
    PA_SYMBOL_NOT_FOUND = DL_ERROR(0x0013),
    PA_OBJ_NAME_TOO_LONG = DL_ERROR(0x0014),
    PA_UNSUPPORTED_RELOCATION_TYPE = DL_ERROR(0x0015),
    PA_MEMORY_INVALID_SIZE = DL_ERROR(0x0016),
    PA_MEMORY_ENCLAVE_MALLOC_FAILED = DL_ERROR(0x0017),
    PA_MEMORY_NO_FREE_SPACE_FOUND = DL_ERROR(0x0018),
    PA_MEMORY_INVALID_POINTER = DL_ERROR(0x0019),
    PA_MEMORY_MEMORY_NOT_IN_USE = DL_ERROR(0x001a),
    PA_MALLOC_FAILED = DL_ERROR(0x001b),
    PA_CANT_CALCULATE_FILE_SIZE = DL_ERROR(0x001c),
    PA_MUNMAP_FAILED = DL_ERROR(0x001d),
    PA_MMAP_FAILED = DL_ERROR(0x001e),
    PA_SYMTAB_NOT_FOUND = DL_ERROR(0x001f),
    PA_CLOSE_FAILED = DL_ERROR(0x0020),
    PA_ENCLAVE_FCT_TABLE_ALREADY_EXISTS = DL_ERROR(0x0021),
    PA_CANT_CHANGE_PAGE_PERMISSIONS = DL_ERROR(0x0022),
    PA_THREAD_INVALID_MUTEX = DL_ERROR(0x0023),
    PA_THREAD_UNLOCK_MUTEX = DL_ERROR(0x0024),
    PA_NO_SYMBOLS_IN_FILE = DL_ERROR(0x0025),
    PA_FUNCTION_BLOCKED = DL_ERROR(0x0026),
    PA_FUNCTION_LOADING = DL_ERROR(0x0027),
	PA_UNRESOLVED_RELOCATION = DL_ERROR(0x0028),
	PA_INCOMPATIBLE_PAGE_TYPE = DL_ERROR(0x4001),
	PA_UPGRADE_LOCK_ERROR = DL_ERROR(0x5000),
	PA_HASH_MISMATCH = DL_ERROR(0x6000),
	PA_SYMTAB_HASH_MISMATCH = DL_ERROR(0x6001),
	PA_STRTAB_HASH_MISMATCH = DL_ERROR(0x6002),
	DL_SEAL_FAILED = DL_ERROR(0x6003),
	DL_HASH_FAILED = DL_ERROR(0x6004),
	PA_CONSISTENCY_ERROR = DL_ERROR(0x9000),
} dl_status_t;

#endif //ENCLAVE_PA_ERROR_H