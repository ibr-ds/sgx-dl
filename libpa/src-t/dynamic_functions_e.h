#ifndef ENCLAVE_DYNAMIC_FUNCTIONS_E_H
#define ENCLAVE_DYNAMIC_FUNCTIONS_E_H

#include <stdint.h>
#include <stdbool.h>
#include "elf_parser.h"
#include "pa.h"
#include "__enclave.h"
#include "rwlock.h"

#ifndef PA_MAX_OBJ_NAME_LENGTH
#define PA_MAX_OBJ_NAME_LENGTH 64
#endif

typedef enum
{
	_pa_fct_zero_state = 0x0,
	_pa_fct_loaded = 0b1,
	_pa_fct_not_loaded = ~_pa_fct_loaded,
	_pa_fct_is_loading = 0b10,
	_pa_fct_is_not_loading = ~_pa_fct_is_loading,
	_pa_fct_deps_adding = 0b100,
	_pa_fct_no_deps_adding = ~_pa_fct_deps_adding,
} _fct_status_t;

#define _PA_FCT_IS_LOADED(status) ((status) & _pa_fct_loaded)
#define _PA_FCT_IS_LOADING(status) ((status) & _pa_fct_is_loading)
#define _PA_FCT_IS_DEPS_ADDING(status) ((status) & _pa_fct_deps_adding)

struct obj_table;

typedef struct fct_table _pa_fct_table_t;
typedef struct obj_table _pa_obj_table_t;

typedef struct file_table
{
	struct file_table *pred;
	struct file_table *succ;
	uint64_t id;
	struct obj_table *_local_obj_table;
	_pa_fct_table_t *_fct_table;
	void *elf_header;
	uint64_t symbol_table_entries;
	elf_symbol_t *symbol_table;
	char *string_table;
	char *section_header_string_table;
} _pa_file_table_t;

typedef struct lru_table
{
	struct lru_table *pred, *succ;
	_pa_fct_table_t *fct;
} _pa_fct_lru_table_t;

typedef struct rel_table
{
	struct rel_table *succ;
	elf_relocation_t *rel;
} _pa_fct_rel_table_t;

typedef struct
{
	void *addr;
	char *fct_name;
} _pa_enclave_fct_table_t;

typedef struct relocation
{
	elf_relocation_t elfrel;
	struct {
		Elf_Addr value;
		unsigned char info;
	} symbol;
	unsigned char symbol_name[PA_MAX_FCT_NAME_LENGTH];
	unsigned char resolved;
	union {
		_pa_fct_table_t *fct;
		_pa_obj_table_t *obj;
		_pa_enclave_fct_table_t *encl_fct;
	} ref;
} _pa_relocation_t;

typedef struct parent_relocation
{
	struct parent_relocation *next;
	_pa_fct_table_t *parent;
	_pa_relocation_t *rel;
} _pa_parent_relocation_t;

typedef struct indirect_dependency
{
	struct indirect_dependency *next;
	_pa_fct_table_t *fct;
} _pa_indirect_dependency_t;

typedef struct obj_table
{
	struct obj_table *pred;
	struct obj_table *succ;
	char name[PA_MAX_OBJ_NAME_LENGTH];
	void *addr;
	size_t size;
	uint64_t alignment;
	uint64_t alignment_offset;
	uint16_t version;
	_pa_file_table_t *file;

	_pa_relocation_t *resolved_relocations;
	uint64_t relocation_entries;
} _pa_obj_table_t;

typedef struct fct_table
{
	struct fct_table *pred;
	struct fct_table *succ;

	bool edge_fct;

	dl_fct_id_t id;
	unsigned char fct_name[PA_MAX_FCT_NAME_LENGTH];
	uint16_t version;

	void *sealed_opcode;
	sgx_sha256_hash_t opcode_hash;
	uint32_t sealed_size;
	uint64_t opcode_size;
	void *addr;

	_pa_relocation_t *resolved_relocations;
	uint64_t relocation_entries;
	_pa_parent_relocation_t *parent_relocations;
	_pa_indirect_dependency_t *indirect_dependencies;

	_fct_status_t status;

	_pa_file_table_t *file_table_entry;

	unsigned int calls_in_progress;

	_pa_fct_lru_table_t *lru_entry;
} _pa_fct_table_t;

static dl_status_t _pa_copy_relocations(_pa_fct_table_t *fct, elf_header_t *elf, int64_t rela_section_index);
static dl_status_t _pa_add_fct_ex(dl_file_handle_t file_handle, const char *fct_name, _pa_fct_table_t **fct_table_ptr, _pa_fct_table_t **ret_fct_ptr);

static dl_status_t _pa_find_func_memory(_pa_fct_table_t *fct);
dl_status_t _pa_load_fct_ex(_pa_fct_table_t *fct_table_ptr);
static dl_status_t _pa_load_dependencies(_pa_fct_table_t *fct);

static inline _pa_fct_table_t *_pa_find_sym_by_id(dl_fct_id_t id, _pa_fct_table_t *table);
static inline _pa_obj_table_t *_pa_find_obj_by_name(const char *name, uint16_t version, _pa_obj_table_t *table);
static inline _pa_fct_table_t *_pa_find_sym_by_name(const char *name, _pa_fct_table_t *table);

static uint64_t _pa_add_parent_relocation(_pa_fct_table_t *child, _pa_fct_table_t *parent, _pa_relocation_t *parent_relocation);
static uint64_t _pa_resolve_all_relocations();
static uint64_t _pa_resolve_relocations(_pa_fct_table_t *fct);
static uint64_t _pa_resolve_obj_relocations(_pa_obj_table_t *_obj);
static uint64_t _pa_add_all_indirect_dependencies(_pa_fct_table_t *child, _pa_fct_table_t *parent);
static uint64_t _pa_add_to_indirect_dependencies(_pa_fct_table_t *parent, _pa_fct_table_t *child);
static void _pa_relocate_objs();
static dl_status_t _pa_relocate_obj(_pa_obj_table_t *obj);

static dl_status_t _pa_add_obj(const char *name, dl_file_handle_t file_handle, _pa_obj_table_t **obj_table_ptr, _pa_obj_table_t **ptr);

dl_status_t _pa_relocation(Elf_Word rel_type, Elf_SDword addend, void *destination_ptr, void **data_ptr, uint64_t alignment_offset);

dl_status_t _pa_unload_fct_ex(_pa_fct_table_t *fct_ptr);

static dl_status_t _pa_update_fct_ex(dl_file_handle_t hndl, const char *fct_name, void* file_ptr);

static dl_status_t _pa_update_lru_table(_pa_fct_lru_table_t *entry_ptr);

static dl_status_t _pa_remove_lru_table(_pa_fct_lru_table_t *entry_ptr);

#endif //ENCLAVE_DYNAMIC_FUNCTIONS_E_H
