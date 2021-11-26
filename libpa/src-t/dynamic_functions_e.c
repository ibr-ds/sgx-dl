#include "__debug.h"
#include "dynamic_functions_e.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sgx_thread.h>
#include <sgx.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <dl_patch.h>

#include "rwlock.h"
#include "memory_allocator.h"
#include "elf_parser.h"

#define DISABLE_ENCL_HASH_CHECK

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define cpu_relax() __asm__ volatile("pause": : :"memory")
#define max(a, b) ((a) > (b) ? (a) : (b))

#ifdef ASLR_IN_BAND

extern rwlock_t shuffling_lock;
extern uint64_t aslr_current_call_counter;
dl_status_t _dl_shuffle_fct_addresses();
#else
#ifdef ASLR_OUT_BAND

static uint64_t fct_call_cnt_since_last_shuffle = 0; 	 //This will be incremented if shuffling status reaches 0 and will be reseted if the shuffling status > 0
static uint64_t max_fct_calls_possible_since_last_shuffle = 1000; //This will be randomised upon first violation

extern rwlock_t shuffling_lock;
extern volatile int shuffling_state;

#endif
#endif

_pa_fct_table_t *_fct_table = NULL;
_pa_file_table_t *_file_table = NULL;
_pa_obj_table_t *_obj_table = NULL;
rwlock_t table_lock = 0;
static uint64_t __dl_file_handle_id = 0;
static uint64_t __dl_fct_id = 0;
static uint32_t function_counter = 0;
static uint32_t object_counter = 0;

static _pa_fct_lru_table_t *_lru_first = NULL, *_lru_last = NULL;
static rwlock_t lru_lock = 0;

char _dl_error_msg[1024] = {};

static _pa_enclave_fct_table_t *_enclave_fct_table = NULL;
static unsigned int _enclave_fct_counter = 0;
extern uint8_t __ImageBase;

#ifdef DEBUG
void print_fct_table(_pa_fct_table_t* ptr)
{
	if(ptr == NULL)
	{
		debug_print("Nothing to show");
	}
	while(ptr != NULL)
	{
		debug_print_fct_table_t(ptr);
		ptr = ptr->succ;
	}
}

void print_file_table(void)
{
	_pa_file_table_t* ptr = _file_table;
	if(ptr == NULL)
	{
		debug_print("Nothing to show");
	}
	while(ptr != NULL)
	{
		debug_print_file_table_t(ptr);
		ptr = ptr->succ;
	}
}
#endif

__attribute__((weak)) void ocall_print_string(const char *u)
{
	(void)u;
}

void debug_printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

dl_status_t dl_add_enclave_fct(char *enclave_path, sgx_sha256_hash_t *symhash, sgx_sha256_hash_t *strhash)
{
	write_lock(&table_lock);

	if (_enclave_fct_table != NULL)
	{
		write_unlock(&table_lock);
		return PA_ENCLAVE_FCT_TABLE_ALREADY_EXISTS;
	}

	struct elf_section_symtab_t sections;
	dl_status_t status;
	_pa_get_symtab(&status, &sections, enclave_path);

	if (status != DL_SUCCESS)
	{
		write_unlock(&table_lock);
		return status;
	}

	elf_section_header_t *symtab_header = sections.symtab_section_header;
	elf_symbol_t *symtab_section = sections.symtab_section;
	char *symtab_string_section = sections.symtab_string_section;

	// copy symtab into enclave
	uint32_t symtab_size = (uint32_t) symtab_header->size;
	uint32_t symtab_entsize = (uint32_t) symtab_header->entsize;
	elf_symbol_t *encl_symtab = calloc(1, symtab_size);
	memcpy(encl_symtab, symtab_section, symtab_size);
	sgx_sha256_hash_t newhash;
	sgx_sha256_msg((uint8_t*)encl_symtab, symtab_size, &newhash);
	if (memcmp(&newhash, *symhash, SGX_SHA256_HASH_SIZE) != 0)
	{
		char exp[SGX_SHA256_HASH_SIZE*2 + 1] = {};
		char got[SGX_SHA256_HASH_SIZE*2 + 1] = {};
		for (size_t i = 0; i < SGX_SHA256_HASH_SIZE; ++i)
		{
			snprintf(exp+2*i, SGX_SHA256_HASH_SIZE*2 - 2*i, "%02x", (*symhash)[i]);
			snprintf(got+2*i, SGX_SHA256_HASH_SIZE*2 - 2*i, "%02x", newhash[i]);
		}
		snprintf(_dl_error_msg, sizeof(_dl_error_msg) - 1, "symtab hash mismatch. Expected:\n%s\nCalculated:\n%s\n", exp, got);
#ifndef DISABLE_ENCL_HASH_CHECK
		return PA_SYMTAB_HASH_MISMATCH;
#endif
	}
	symtab_section = encl_symtab;

	// copy symtab string section
	uint32_t string_size = sections.symtab_string_section_length;
	char *encl_string = calloc(1, string_size);
	memcpy(encl_string, sections.symtab_string_section, string_size);
	sgx_sha256_msg((uint8_t *)encl_string, string_size, &newhash);
	if (memcmp(&newhash, *strhash, SGX_SHA256_HASH_SIZE) != 0)
	{
		char exp[SGX_SHA256_HASH_SIZE*2 + 1] = {};
		char got[SGX_SHA256_HASH_SIZE*2 + 1] = {};
		for (size_t i = 0; i < SGX_SHA256_HASH_SIZE; ++i)
		{
			snprintf(exp+2*i, SGX_SHA256_HASH_SIZE*2 - 2*i, "%02x", (*strhash)[i]);
			snprintf(got+2*i, SGX_SHA256_HASH_SIZE*2 - 2*i, "%02x", newhash[i]);
		}
		snprintf(_dl_error_msg, sizeof(_dl_error_msg) - 1, "strtab hash mismatch. Expected:\n%s\nCalculated:\n%s\n", exp, got);
#ifndef DISABLE_ENCL_HASH_CHECK
		free(symtab_section);
		return PA_STRTAB_HASH_MISMATCH;
#endif
	}
	symtab_string_section = encl_string;

	for (int i = 0; i < (symtab_size / symtab_entsize); i++)
	{
		if (ELF_S_TYPE(symtab_section[i].info) == symbol_type_fct && ELF_S_BIND(symtab_section[i].info) == symbol_binding_local)
		{
			_enclave_fct_counter++;
		}
	}

	if ((_enclave_fct_table = (_pa_enclave_fct_table_t *) calloc(sizeof(_pa_enclave_fct_table_t), _enclave_fct_counter)) == NULL)
	{
		_pa_unmap_enclave(&status);

		if (status != DL_SUCCESS)
		{
			write_unlock(&table_lock);
			free(symtab_section);
			free(symtab_string_section);
			return status;
		}

		_enclave_fct_counter = 0;

		write_unlock(&table_lock);
		free(symtab_section);
		free(symtab_string_section);
		return PA_MALLOC_FAILED;
	}

	for (int i = 0, j = 0; i < (symtab_size / symtab_entsize); i++)
	{
		if (ELF_S_TYPE(symtab_section[i].info) == symbol_type_fct && ELF_S_BIND(symtab_section[i].info) == symbol_binding_local)
		{
			_enclave_fct_table[j].addr = ((void *) &__ImageBase) + symtab_section[i].value;
			size_t fct_name_length = (strlen(&symtab_string_section[symtab_section[i].name_offset]) + 1);

			if ((_enclave_fct_table[j].fct_name = (char *) calloc(sizeof(char), fct_name_length)) == NULL)
			{
				abort();
			}

			memcpy(_enclave_fct_table[j].fct_name, &symtab_string_section[symtab_section[i].name_offset], fct_name_length);
#ifdef DEBUG
			debug_print_enclave_fct_table_t(&_enclave_fct_table[j]);
#endif
			j++;
		}
	}

	_pa_unmap_enclave(&status);

	if (status != DL_SUCCESS)
	{
		write_unlock(&table_lock);
		free(symtab_section);
		free(symtab_string_section);
		return status;
	}

	// Resolve all reloactions

	while (_pa_resolve_all_relocations() != 0);

	write_unlock(&table_lock);
	free(symtab_section);
	free(symtab_string_section);
	return DL_SUCCESS;

}

static dl_status_t _dl_add_file(void *file_ptr, dl_file_handle_t *file_handle)
{
	dl_status_t status = DL_SUCCESS;
	_pa_file_table_t *new_file_entry = _file_table;
	_pa_file_table_t *localptr = NULL;
	elf_header_t *elf_header = (elf_header_t *)file_ptr;
	elf_section_header_t *section_headers = file_ptr + elf_header->section_header_offset;

	// Iterate over the file list to see if we added it before
	// TODO: check if we already know the file, maybe calc a hash of the elf header or something?
	while (new_file_entry != NULL)
	{
		localptr = new_file_entry;
		new_file_entry = new_file_entry->succ;
	}

	if (new_file_entry == NULL)
	{
		// We did not add it before, so do it now

		if (_file_table == NULL)
		{
			if ((new_file_entry = calloc(1, sizeof(_pa_file_table_t))) == NULL)
			{
				abort();
			}

			new_file_entry->pred = NULL;
			_file_table = new_file_entry;
		}
		else
		{
			if ((new_file_entry = calloc(1, sizeof(_pa_file_table_t))) == NULL)
			{
				abort();
			}
			localptr->succ = new_file_entry;
			new_file_entry->pred = localptr;
		}

		*file_handle = ++__dl_file_handle_id;

		new_file_entry->succ = NULL;
		new_file_entry->id = *file_handle;
		new_file_entry->_local_obj_table = NULL;
		new_file_entry->_fct_table = NULL;
		new_file_entry->elf_header = elf_header;
		new_file_entry->symbol_table = NULL;
		new_file_entry->string_table = NULL;
		new_file_entry->section_header_string_table = NULL;

		for (int i = 0; i < elf_header->sectionHeaderCount; i++)
		{
			if (section_headers[i].type == section_type_symtab)
			{
				// Copy symbol table into enclave
				uint64_t symbol_table_size = section_headers[i].size;
				new_file_entry->symbol_table = malloc(symbol_table_size);
				if (new_file_entry->symbol_table == NULL)
				{
					abort();
				}
				memcpy(new_file_entry->symbol_table, file_ptr + section_headers[i].offset, symbol_table_size);
				new_file_entry->symbol_table_entries = symbol_table_size / section_headers[i].entsize;

				// TODO: make this one malloc...

				// Copy symbol and section header string table into enclave
				elf_section_header_t *string_table = section_headers + section_headers[i].link;
				elf_section_header_t *section_header_string_table = section_headers + elf_header->section_header_string_table_index;
				uint64_t string_table_size = string_table->size;
				uint64_t section_header_string_table_size = section_headers[elf_header->section_header_string_table_index].size;
				new_file_entry->string_table = malloc(string_table_size + section_header_string_table_size);
				if (new_file_entry->string_table == NULL)
				{
					abort();
				}
				new_file_entry->section_header_string_table = new_file_entry->string_table + string_table_size;
				memcpy(new_file_entry->string_table, file_ptr + string_table->offset, string_table_size);
				memcpy(new_file_entry->section_header_string_table, file_ptr + section_header_string_table->offset, section_header_string_table_size);
				break;
			}
		}

		if (new_file_entry->symbol_table == NULL)
		{
			// We did not find a symbol table inside the file
			// FIXME: this will leak memory as we might have allocated some before
			write_unlock(&table_lock);
			return PA_NO_SYMBOLS_IN_FILE;
		}

		// Create local and global symbols
		// First, iterate over symbol table
		elf_symbol_t *symbol = NULL;
		_pa_obj_table_t **objtable = NULL;
		_pa_obj_table_t *object = NULL;
		char *symbol_name = NULL;
		for (uint64_t i = 0; i < new_file_entry->symbol_table_entries; ++i)
		{
			symbol = new_file_entry->symbol_table + i;
			symbol_name = new_file_entry->string_table + symbol->name_offset;

			if (ELF_S_TYPE(symbol->info) == symbol_type_obj)
			{

				if (ELF_S_BIND(symbol->info) == symbol_binding_global)
				{
					objtable = &_obj_table;
				}
				else if (ELF_S_BIND(symbol->info) == symbol_binding_local)
				{
					//symbol_name = symbol_section_name;
					objtable = &new_file_entry->_local_obj_table;
				}

				object = _pa_find_obj_by_name(symbol_name, 0, *objtable);

				if (object == NULL)
				{
					status = _pa_add_obj(symbol_name, *file_handle, objtable, &object);
					//object->section_header_index = symbol->sHeaderIndex;
					if (status != DL_SUCCESS)
					{
						return status;
					}

					object->size = symbol->size;
					if (_pa_malloc_data(&object->addr, symbol->size) != DL_SUCCESS)
					{
						abort();
					}

					// Initialize the object with the correct data
					if (symbol->sHeaderIndex != section_index_common && section_headers[symbol->sHeaderIndex].type != section_type_nobits)
					{
						elf_get_section_data(object->addr, symbol->size, section_headers[symbol->sHeaderIndex].offset, elf_header);
					}
					else if (symbol->sHeaderIndex != section_index_common && section_headers[symbol->sHeaderIndex].type == section_type_nobits)
					{
						memset(object->addr, 0, symbol->size);
					}
					object_counter++;
#ifdef DEBUG
					debug_print_obj_table_t(object);
#endif
				}
				else
				{
					// we want to add an object that already exists???
					abort();
				}
			}
			else if (ELF_S_TYPE(symbol->info) == symbol_type_fct && ELF_S_BIND(symbol->info) == symbol_binding_local)
			{
				_pa_fct_table_t *new_fct = NULL;
				status = _pa_add_fct_ex(*file_handle, symbol_name, &new_file_entry->_fct_table, &new_fct);
				if (status != DL_SUCCESS)
				{
					abort();
				}
				function_counter++;
			}
		}
	}

	while (_pa_resolve_all_relocations() != 0);

	return DL_SUCCESS;
}

dl_status_t dl_add_file(void *file_ptr, dl_file_handle_t *file_handle)
{
	if (file_ptr == NULL || file_handle == NULL)
	{
		return PA_INVALID_POINTER;
	}

	if (*file_handle != DL_EMPTY_HANDLE)
	{
		return PA_INVALID_FILE_ID;
	}

	dl_status_t status = elf_check_header(file_ptr);
	if (status != DL_SUCCESS)
	{
		return status;
	}

	write_lock(&table_lock);

	status = _dl_add_file(file_ptr, file_handle);

	write_unlock(&table_lock);

	return status;
}

/**
 * @brief You need to hold a write lock to use this function
 * @param file_handle
 * @param fct_name
 * @param fct_table_ptr
 * @param ret_fct_ptr
 * @return
 */
static dl_status_t _pa_add_fct_ex(dl_file_handle_t file_handle, const char *fct_name, _pa_fct_table_t **fct_table_ptr, _pa_fct_table_t **ret_fct_ptr)
{
	//Important checks to detect invalid pointers or an invalid elf-file
	if (file_handle == DL_EMPTY_HANDLE || fct_table_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	_pa_file_table_t *file_entry = _file_table;
	while (file_entry != NULL)
	{
		if (file_entry->id == file_handle)
		{
			break;
		}

		file_entry = file_entry->succ;
	}
	if (file_entry == NULL)
	{
		return PA_INVALID_FILE_ID;
	}

	// No function name given, so we are done here
	if (fct_name == NULL)
	{
		while (_pa_resolve_all_relocations() != 0);
		return DL_SUCCESS;
	}

	elf_header_t *elf_header = (elf_header_t *)file_entry->elf_header;
	elf_section_header_t *section_headers = (void *)elf_header + elf_header->section_header_offset;
	_pa_fct_table_t *new_fct_entry = NULL;

	// Function name is set so not only add the file but also add a function from it
	if (strlen(fct_name) + 1 > PA_MAX_FCT_NAME_LENGTH)
	{
		return PA_FUNCTION_NAME_TOO_LONG;
	}

	char *rela_section_name, *text_section_name;

	if ((rela_section_name = malloc(strlen(PREFIX_RELA) + strlen(PREFIX_TEXT) + strlen((const char *) fct_name) + 1)) == NULL)
	{
		abort();
	}

	text_section_name = rela_section_name + strlen(PREFIX_RELA);
	memcpy(rela_section_name, PREFIX_RELA, strlen(PREFIX_RELA));
	memcpy(text_section_name, PREFIX_TEXT, strlen(PREFIX_TEXT));
	memcpy(text_section_name + strlen(PREFIX_TEXT), fct_name, strlen((const char *) fct_name) + 1);

	int64_t text_section_index = -1, rela_section_index = -1;

	for (unsigned int i = 0; (i < elf_header->sectionHeaderCount) && (text_section_index == -1 || rela_section_index == -1); i++)
	{
#ifdef DEBUG_PA_ADD_FCT_EX_SECTION_HEADER
		debug_print_elf_section_header(&new_file_entry->section_header[i],section_string_table,i);
#endif
		if (!strcmp(text_section_name, (const char *) &file_entry->section_header_string_table[section_headers[i].name_offset]))
		{
			text_section_index = i;
		}
		else if (!strcmp(rela_section_name, (const char *) &file_entry->section_header_string_table[section_headers[i].name_offset]))
		{
			rela_section_index = i;
		}
	}

	free(rela_section_name);

	if (text_section_index == -1)
	{
		return PA_FUNCTION_NOT_FOUND;
	}

	// Add new element into function list
	if (*fct_table_ptr == NULL)
	{
		*fct_table_ptr = (_pa_fct_table_t *) calloc(1, sizeof(_pa_fct_table_t));

		if (*fct_table_ptr == NULL)
		{
			abort();
		}

		new_fct_entry = *fct_table_ptr;
		new_fct_entry->pred = NULL;
	}
	else
	{
		_pa_fct_table_t *it = *fct_table_ptr;
		while (it->succ != NULL)
		{
			if (!strcmp((const char *) it->fct_name, (const char *) fct_name))
			{
				return PA_FUNCTION_ALREADY_EXISTS;
			}

			it = it->succ;
		}

		if (!strcmp((const char *) it->fct_name, (const char *) fct_name))
		{
			return PA_FUNCTION_ALREADY_EXISTS;
		}

		if ((new_fct_entry = (_pa_fct_table_t *) calloc(1, sizeof(_pa_fct_table_t))) == NULL)
		{
			return PA_MALLOC_FAILED;
		}

		it->succ = new_fct_entry;
		new_fct_entry->pred = it;
	}

	new_fct_entry->id = ++__dl_fct_id;
	new_fct_entry->resolved_relocations = NULL;
	new_fct_entry->relocation_entries = 0;
	new_fct_entry->parent_relocations = NULL;
	new_fct_entry->indirect_dependencies = NULL;
	new_fct_entry->addr = NULL;
	new_fct_entry->succ = NULL;
	new_fct_entry->file_table_entry = file_entry;
	new_fct_entry->status = _pa_fct_zero_state;
	new_fct_entry->calls_in_progress = 0;
	new_fct_entry->lru_entry = NULL;
	new_fct_entry->version = 0;
	new_fct_entry->edge_fct = false;

	strncpy((char *) (new_fct_entry)->fct_name, fct_name, PA_MAX_FCT_NAME_LENGTH - 1);

	if (ret_fct_ptr != NULL)
	{
		*ret_fct_ptr = new_fct_entry;
	}

	dl_status_t status = DL_SUCCESS;

	// Copy relocation table
	if (rela_section_index != -1)
	{
		if ((status = _pa_copy_relocations(new_fct_entry, elf_header, rela_section_index)) != DL_SUCCESS)
		{
			free(new_fct_entry);
			return status;
		}
	}

	// Seal + hash opcode
	elf_section_header_t *text_section_header = section_headers + text_section_index;
	void *opcode = (void*)elf_header + text_section_header->offset;
	sgx_status_t ret = sgx_sha256_msg(opcode, text_section_header->size, &new_fct_entry->opcode_hash);
	if (ret != SGX_SUCCESS)
	{
		free(new_fct_entry);
		return DL_HASH_FAILED;
	}
	new_fct_entry->sealed_size = sgx_calc_sealed_data_size(0, text_section_header->size);
	new_fct_entry->opcode_size = text_section_header->size;
	sgx_sealed_data_t *sealed_data = malloc(new_fct_entry->sealed_size);
	uint8_t _copy_to_enclave = 0;
	if (sgx_is_outside_enclave(opcode, new_fct_entry->opcode_size))
	{
		// move opcode inside enclave for sealing
		opcode = malloc(new_fct_entry->opcode_size);
		if (opcode == NULL)
		{
			free(new_fct_entry);
			return PA_MALLOC_FAILED;
		}
		_copy_to_enclave = 1;
		memcpy(opcode, (void*)elf_header + text_section_header->offset, new_fct_entry->opcode_size);
	}

	if (sealed_data == NULL)
	{
		free(new_fct_entry);
		return PA_MALLOC_FAILED;
	}
	ret = sgx_seal_data(0, NULL, new_fct_entry->opcode_size, opcode, new_fct_entry->sealed_size, sealed_data);
	if (ret != SGX_SUCCESS)
	{
		free(sealed_data);
		free(new_fct_entry);
		return DL_SEAL_FAILED;
	}

	ret = ocall_malloc(&new_fct_entry->sealed_opcode, new_fct_entry->sealed_size);
	if (ret != SGX_SUCCESS)
	{
		free(sealed_data);
		free(new_fct_entry);
		return PA_MALLOC_FAILED;
	}

	memcpy(new_fct_entry->sealed_opcode, sealed_data, new_fct_entry->sealed_size);
	free(sealed_data);
	if (_copy_to_enclave == 1)
	{
		free(opcode);
	}

	while (_pa_resolve_all_relocations() != 0);

	return status;
}

static dl_status_t _pa_copy_relocations(_pa_fct_table_t *fct, elf_header_t *elf, int64_t rela_section_index)
{
	elf_section_header_t *section_headers = ((void *)elf) + elf->section_header_offset;
	elf_section_header_t *rela_section_header = section_headers + rela_section_index;
	elf_relocation_t *relocations = ((void *)elf) + rela_section_header->offset;

	fct->relocation_entries = rela_section_header->size / rela_section_header->entsize;
	fct->resolved_relocations = calloc(fct->relocation_entries, sizeof(_pa_relocation_t));
	if (fct->resolved_relocations == NULL)
	{
		return PA_MALLOC_FAILED;
	}

	// patch relocation table
	for (uint64_t i = 0; i < fct->relocation_entries; ++i)
	{
		fct->resolved_relocations[i].elfrel = relocations[i];

		// We are looking for local relocations
		elf_symbol_t symbol = fct->file_table_entry->symbol_table[ELF_R_SYM(relocations[i].info)];
		char *symbol_name = fct->file_table_entry->string_table + symbol.name_offset;
		elf_symbol_types symbol_type = ELF_S_TYPE(symbol.info);
		elf_symbol_bindings symbol_binding = ELF_S_BIND(symbol.info);
		if (symbol_binding == symbol_binding_local &&
		    symbol_type == symbol_type_section)
		{
			// Handle .rodata
			if (symbol.sHeaderIndex < 0xff00)
			{
				char *symbol_section_name = fct->file_table_entry->section_header_string_table + (section_headers[symbol.sHeaderIndex].name_offset);
				if (!strncmp(PREFIX_RODATA, (const char *) symbol_section_name, 7))
				{
#ifdef DEBUG
					//debug_print_elf_symbol(symbol, symbol_section_name);
					//debug_print("Patching Symbol type");
#endif
					// Set the type to object
					symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);

					// We now need to copy .rodata into enclave if it does not yet exists
					_pa_obj_table_t *rodata = _pa_find_obj_by_name(symbol_section_name, fct->version, fct->file_table_entry->_local_obj_table);
					if (rodata == NULL)
					{
						_pa_add_obj(symbol_section_name, fct->file_table_entry->id, &fct->file_table_entry->_local_obj_table, &rodata);
						elf_section_header_t *rodata_section = section_headers + symbol.sHeaderIndex;
						rodata->size = rodata_section->size;
						if(_pa_malloc_data(&rodata->addr, rodata_section->size) != DL_SUCCESS)
						{
							abort();
						}

						// Move rodata->addr by enough bytes so that the alignment fits
						rodata->alignment = rodata_section->addralign;
						rodata->alignment_offset = ((uint64_t)rodata->addr) % rodata_section->addralign;
						if (rodata->alignment_offset != 0)
						{
							rodata->size += rodata->alignment_offset;
							if(_pa_free(rodata->addr) != DL_SUCCESS)
							{
							    abort();
							}

							if(_pa_malloc_data(&rodata->addr, rodata_section->size + rodata->alignment_offset) != DL_SUCCESS)
							{
								abort();
							}
						}

						memcpy(rodata->addr + rodata->alignment_offset, ((void *) elf) + rodata_section->offset, rodata_section->size);
						object_counter++;
					}
					symbol_name = symbol_section_name;

#ifdef DEBUG
					//debug_print_elf_symbol(symbol,symbol_name);
#endif
				}
			}


			// Find the real symbol
			for (uint64_t j = 0; j < fct->file_table_entry->symbol_table_entries; ++j)
			{
				elf_symbol_t *temp = fct->file_table_entry->symbol_table + j;
				if (temp->sHeaderIndex == symbol.sHeaderIndex &&
				    ELF_S_TYPE(temp->info) != symbol_type_section &&
				    temp->name_offset != 0)
				{
					// Found a symbol pointing to the same section with a name that is not a section
					fct->resolved_relocations[i].elfrel.info = ELF_R_INFO(j, ELF_R_TYPE(relocations[i].info));
					symbol.info = (unsigned char) ELF_S_INFO(ELF_S_BIND(symbol.info), ELF_S_TYPE(temp->info));
					symbol_name = fct->file_table_entry->string_table + temp->name_offset;
					break;
				}
			}
		}  // END IF local symbol that is a section
		else if (symbol_binding == symbol_binding_local &&
		         symbol_type == symbol_type_notype)
		{
			// handle some Rust symbols
			// Add the section as a local object and change the relocation to object
			char *local_symbol_name = fct->file_table_entry->string_table + symbol.name_offset;
			elf_section_header_t s = section_headers[symbol.sHeaderIndex];

			char *symbol_section_name = fct->file_table_entry->section_header_string_table + (section_headers[symbol.sHeaderIndex].name_offset);
			if (!strncmp(PREFIX_RODATA, (const char *) symbol_section_name, 7))
			{
				// symbol points to .rodata, replace smybol name and only store .rodata object
				symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);

				// We now need to copy .rodata into enclave if it does not yet exists
				// We just assume, that the .rodata obj simply has no name
				_pa_obj_table_t *rodata = _pa_find_obj_by_name(symbol_section_name, fct->version, fct->file_table_entry->_local_obj_table);
				if (rodata == NULL)
				{
					if (_pa_add_obj(symbol_section_name, fct->file_table_entry->id, &fct->file_table_entry->_local_obj_table, &rodata) != DL_SUCCESS)
					{
						abort();
					}
					elf_section_header_t *rodata_section = section_headers + symbol.sHeaderIndex;
					rodata->size = rodata_section->size + rodata_section->addralign;
					rodata->alignment = rodata_section->addralign;
					if(_pa_malloc_data(&rodata->addr, rodata_section->size + rodata_section->addralign) != DL_SUCCESS)
					{
						abort();
					}

					// Move rodata->addr by enough bytes so that the alignment fits
					rodata->alignment_offset = ((uint64_t)rodata->addr) % rodata_section->addralign;

					memcpy(rodata->addr + rodata->alignment_offset, ((void *) elf) + rodata_section->offset, rodata_section->size);
					object_counter++;
				}
				symbol_name = symbol_section_name;
			}
			else
			{
				_pa_obj_table_t *obj = _pa_find_obj_by_name(local_symbol_name, fct->version, fct->file_table_entry->_local_obj_table);
				if (obj == NULL)
				{
					_pa_add_obj(local_symbol_name, fct->file_table_entry->id, &fct->file_table_entry->_local_obj_table, &obj);
					obj->size = s.size;
					if (_pa_malloc_data(&obj->addr, s.size))
					{
						abort();
					}
					memcpy(obj->addr, ((void *) elf) + s.offset, s.size);
					object_counter++;
				}
				symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);
			}
		}

		fct->resolved_relocations[i].resolved = 0;
		fct->resolved_relocations[i].symbol.info = symbol.info;
		fct->resolved_relocations[i].symbol.value = symbol.value;
		strncpy((char *) fct->resolved_relocations[i].symbol_name, (const char *) symbol_name, PA_MAX_FCT_NAME_LENGTH - 1);

	} // END FOR

	return DL_SUCCESS;
}

static dl_status_t _pa_copy_obj_relocations(_pa_obj_table_t *obj, elf_header_t *elf, int64_t rela_section_index)
{
	elf_section_header_t *section_headers = ((void *)elf) + elf->section_header_offset;
	elf_section_header_t *rela_section_header = section_headers + rela_section_index;
	elf_relocation_t *relocations = ((void *)elf) + rela_section_header->offset;

	obj->relocation_entries = rela_section_header->size / rela_section_header->entsize;
	obj->resolved_relocations = calloc(obj->relocation_entries, sizeof(_pa_relocation_t));
	if (obj->resolved_relocations == NULL)
	{
		return PA_MALLOC_FAILED;
	}

	// patch relocation table
	for (uint64_t i = 0; i < obj->relocation_entries; ++i)
	{
		obj->resolved_relocations[i].elfrel = relocations[i];

		// We are looking for local relocations
		elf_symbol_t symbol = obj->file->symbol_table[ELF_R_SYM(relocations[i].info)];
		char *symbol_name = obj->file->string_table + symbol.name_offset;
		elf_symbol_types symbol_type = ELF_S_TYPE(symbol.info);
		elf_symbol_bindings symbol_binding = ELF_S_BIND(symbol.info);
		if (symbol_binding == symbol_binding_local &&
		    symbol_type == symbol_type_section)
		{
			// Handle .rodata
			if (symbol.sHeaderIndex < 0xff00)
			{
				char *symbol_section_name = obj->file->section_header_string_table + (section_headers[symbol.sHeaderIndex].name_offset);
				if (!strncmp(PREFIX_RODATA, (const char *) symbol_section_name, 7))
				{
#ifdef DEBUG
					//debug_print_elf_symbol(symbol, symbol_section_name);
					//debug_print("Patching Symbol type");
#endif
					// Set the type to object
					symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);

					// We now need to copy .rodata into enclave if it does not yet exists
					_pa_obj_table_t *rodata = _pa_find_obj_by_name(symbol_section_name, 0, obj->file->_local_obj_table);
					if (rodata == NULL)
					{
						_pa_add_obj(symbol_section_name, obj->file->id, &obj->file->_local_obj_table, &rodata);
						elf_section_header_t *rodata_section = section_headers + symbol.sHeaderIndex;
						rodata->size = rodata_section->size;
						if(_pa_malloc_data(&rodata->addr, rodata_section->size) != DL_SUCCESS)
						{
							abort();
						}

						// Move rodata->addr by enough bytes so that the alignment fits
						rodata->alignment = rodata_section->addralign;
						rodata->alignment_offset = ((uint64_t)rodata->addr) % rodata_section->addralign;
						if (rodata->alignment_offset != 0)
						{
							rodata->size += rodata->alignment_offset;
							if(_pa_free(rodata->addr) != DL_SUCCESS)
							{
								abort();
							}

							if(_pa_malloc_data(&rodata->addr, rodata_section->size + rodata->alignment_offset) != DL_SUCCESS)
							{
								abort();
							}
						}

						memcpy(rodata->addr + rodata->alignment_offset, ((void *) elf) + rodata_section->offset, rodata_section->size);
						object_counter++;
					}
					symbol_name = symbol_section_name;

#ifdef DEBUG
					//debug_print_elf_symbol(symbol,symbol_name);
#endif
				}
			}


			// Find the real symbol
			for (uint64_t j = 0; j < obj->file->symbol_table_entries; ++j)
			{
				elf_symbol_t *temp = obj->file->symbol_table + j;
				if (temp->sHeaderIndex == symbol.sHeaderIndex &&
				    ELF_S_TYPE(temp->info) != symbol_type_section &&
				    temp->name_offset != 0)
				{
					// Found a symbol pointing to the same section with a name that is not a section
					obj->resolved_relocations[i].elfrel.info = ELF_R_INFO(j, ELF_R_TYPE(relocations[i].info));
					symbol.info = (unsigned char) ELF_S_INFO(ELF_S_BIND(symbol.info), ELF_S_TYPE(temp->info));
					symbol_name = obj->file->string_table + temp->name_offset;
					break;
				}
			}
		}  // END IF local symbol that is a section
		else if (symbol_binding == symbol_binding_local &&
		         symbol_type == symbol_type_notype)
		{
			// handle some Rust symbols
			// Add the section as a local object and change the relocation to object
			char *local_symbol_name = obj->file->string_table + symbol.name_offset;
			elf_section_header_t s = section_headers[symbol.sHeaderIndex];

			char *symbol_section_name = obj->file->section_header_string_table + (section_headers[symbol.sHeaderIndex].name_offset);
			if (!strncmp(PREFIX_RODATA, (const char *) symbol_section_name, 7))
			{
				// symbol points to .rodata, replace smybol name and only store .rodata object
				symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);

				// We now need to copy .rodata into enclave if it does not yet exists
				// We just assume, that the .rodata obj simply has no name
				_pa_obj_table_t *rodata = _pa_find_obj_by_name(symbol_section_name, 0, obj->file->_local_obj_table);
				if (rodata == NULL)
				{
					_pa_add_obj(symbol_section_name, obj->file->id, &obj->file->_local_obj_table, &rodata);
					elf_section_header_t *rodata_section = section_headers + symbol.sHeaderIndex;
					rodata->size = rodata_section->size + rodata_section->addralign;
					rodata->alignment = rodata_section->addralign;
					if(_pa_malloc_data(&rodata->addr, rodata_section->size + rodata_section->addralign) != DL_SUCCESS)
					{
						abort();
					}

					// Move rodata->addr by enough bytes so that the alignment fits
					rodata->alignment_offset = ((uint64_t)rodata->addr) % rodata_section->addralign;

					memcpy(rodata->addr + rodata->alignment_offset, ((void *) elf) + rodata_section->offset, rodata_section->size);
					object_counter++;
				}
				symbol_name = symbol_section_name;
			}
			else
			{
				_pa_obj_table_t *_obj = _pa_find_obj_by_name(local_symbol_name, 0, obj->file->_local_obj_table);
				if (_obj == NULL)
				{
					_pa_add_obj(local_symbol_name, obj->file->id, &obj->file->_local_obj_table, &_obj);
					_obj->size = s.size;
					if (_pa_malloc_data(&_obj->addr, s.size))
					{
						abort();
					}
					memcpy(_obj->addr, ((void *) elf) + s.offset, s.size);
					object_counter++;
				}
				symbol.info = ELF_S_INFO(ELF_S_BIND(symbol.info), symbol_type_obj);
			}
		}

		obj->resolved_relocations[i].resolved = 0;
		obj->resolved_relocations[i].symbol.info = symbol.info;
		obj->resolved_relocations[i].symbol.value = symbol.value;
		strncpy((char *) obj->resolved_relocations[i].symbol_name, (const char *) symbol_name, PA_MAX_OBJ_NAME_LENGTH - 1);

	} // END FOR

	return DL_SUCCESS;
}


static uint64_t _pa_resolve_all_relocations()
{
	uint64_t changes = 0;

	// Resolve relocations for everyone
	_pa_fct_table_t *it = _fct_table;
	while (it != NULL)
	{
		changes += _pa_resolve_relocations(it);
		changes += _pa_add_all_indirect_dependencies(it, NULL);
		it = it->succ;
	}
	_pa_obj_table_t *ot = _obj_table;
	while (ot != NULL)
	{
		changes += _pa_resolve_obj_relocations(ot);
		ot = ot->succ;
	}
	_pa_file_table_t *fit = _file_table;
	while (fit != NULL)
	{
		it = fit->_fct_table;

		while (it != NULL)
		{
			changes += _pa_resolve_relocations(it);
			changes += _pa_add_all_indirect_dependencies(it, NULL);
			it = it->succ;
		}

		ot = fit->_local_obj_table;
		while (ot != NULL)
		{
			changes += _pa_resolve_obj_relocations(ot);
			ot = ot->succ;
		}

		fit = fit->succ;
	}

	_pa_relocate_objs();

	return changes;
}

static dl_status_t _pa_relocate_obj(_pa_obj_table_t *obj)
{
	dl_status_t status, retval = DL_SUCCESS;
	for (uint64_t i = 0; i < obj->relocation_entries; ++i)
	{
		_pa_relocation_t *rel = obj->resolved_relocations + i;
		if (!rel->resolved)
		{
			continue;
		}

		if (ELF_S_BIND(rel->symbol.info) == symbol_binding_global)
		{

#ifdef DEBUG
			//temp_string_table = found_file_table->string_table;//((void*)found_file_table->file_header) + found_file_table->section_header[found_file_table->symbol_table->link].offset;
				//debug_print("Symbol found:");
				//debug_print_elf_symbol(found_symbol, (char *)&temp_string_table[found_symbol->name_offset]);
#endif
			// At this point we found the global symbol that we need for our relocation
			// found_symbol contains the needed symbol
			// found_file_table the file it has been found in
			// Now we need to check the kind of relocation
			if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
			{
				// Needed symbol is an global object.

				// At this point temp_obj holds the found object
				status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, obj->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
				if (status != DL_SUCCESS)
				{
					retval = status;
					goto ERROR;
				}
			}
			else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
			{
				// The needed symbol is a function.
				// TODO: object relocations to dynamic functions are tricky.
				// TODO: object needs a field to indicate that all relocations are loaded
				// But for know, lets only care about obj relocations
				/*
				_pa_fct_table_t *temp_fct = rel->ref.fct;

				// We found the symbol
				if (!_PA_FCT_IS_LOADED(temp_fct->status) && !_PA_FCT_IS_LOADING(temp_fct->status))
				{
					// The needed symbol is neither currently loaded nor currently in the process of being loaded. We need to load it.
					status = _pa_load_fct_ex(temp_fct);

					// The needed symbol is now loaded.
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else if (_PA_FCT_IS_LOADED(temp_fct->status))
				{
					// The needed symbol is loaded so we need to look at the subcalls of the needed symbol

					_pa_update_lru_table(temp_fct->lru_entry);

					status = _pa_load_dependencies(temp_fct);

					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}

				// Do the actual relocation
				status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &temp_fct->addr, 0);
				if (status != DL_SUCCESS)
				{
					retval = status;
					goto ERROR;
				}
				//*/
			}
			else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_enclave)
			{
				if ((status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, obj->addr + rel->elfrel.offset, &rel->ref.encl_fct->addr, 0)) != DL_SUCCESS)
				{
					retval = status;
					goto ERROR;
				}
			}
			else // needed global symbol is neither function nor object
			{
				retval = PA_UNSUPPORTED_SYMBOL_TYPE;
				goto ERROR;
			}
		} // global symbol end
		else if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
		{
			if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
			{
				// Needed local symbol is an local object

				status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->symbol.value + rel->elfrel.addend, obj->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
				if (status != DL_SUCCESS)
				{
					retval = status;
					goto ERROR;
				}
			}
			else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
			{
				// Needed local symbol is a function
				// TODO: see above...
				/*
				_pa_fct_table_t *temp_fct = NULL;

				// Iterate over all symbols of the file
				temp_fct = rel->ref.fct;

				if (!_PA_FCT_IS_LOADED(temp_fct->status) && !_PA_FCT_IS_LOADING(temp_fct->status))
				{
					// If the needed local symbol is neither loaded nor currently in the process of being loaded we need to load it

					status = _pa_load_fct_ex(temp_fct);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else if (_PA_FCT_IS_LOADED(temp_fct->status))
				{
					// Needed local symbol is loaded

					_pa_update_lru_table(temp_fct->lru_entry);

					status = _pa_load_dependencies(temp_fct);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
#ifdef DEBUG
				debug_print_fct_table_t(temp_fct);
#endif
				// We can now do our relocation
				status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &temp_fct->addr, 0);
				if (status != DL_SUCCESS)
				{
					retval = status;
					goto ERROR;
				}
				 //*/
			}
			else
			{
				retval = PA_UNSUPPORTED_SYMBOL_TYPE;
				goto ERROR;
			}
		} // local symbol end
		else
		{
			// It is neither a local nor global symbol, we cannot work with that
			retval = PA_UNSUPPORTED_SYMBOL_BINDING;
			goto ERROR;
		}
	}
	ERROR:
	return retval;
}

static void _pa_relocate_objs()
{
	_pa_obj_table_t *ot = _obj_table;
	while (ot != NULL)
	{
		_pa_relocate_obj(ot);
		ot = ot->succ;
	}
	_pa_file_table_t *fit = _file_table;
	while (fit != NULL)
	{
		ot = fit->_local_obj_table;
		while (ot != NULL)
		{
			_pa_relocate_obj(ot);
			ot = ot->succ;
		}

		fit = fit->succ;
	}
}

static uint64_t _pa_resolve_relocations(_pa_fct_table_t *fct)
{
	uint64_t changes = 0;
	for (uint64_t i = 0; i < fct->relocation_entries; ++i)
	{
		_pa_relocation_t *rel = fct->resolved_relocations + i;
		if (rel->resolved)
		{
			continue;
		}

		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype)
		{
			char *temp_string_table = NULL;
			_pa_file_table_t *temp_file_table = _file_table;
			elf_symbol_t *temp_symbol_table = NULL;
			elf_symbol_t *found_symbol = NULL;
			// This loop iterates through all added files to find the needed symbol in their symbol table
			while (temp_file_table != NULL)
			{
				temp_symbol_table = temp_file_table->symbol_table;
				temp_string_table = temp_file_table->string_table;

				for (int entry = 0; entry < temp_file_table->symbol_table_entries; entry++)
				{
#ifdef DEBUG_PA_LOAD_FCT_EX_GLOBAL_SYMBOL
					debug_print_elf_symbol(&temp_symbol_table[entry],&temp_string_table[temp_symbol_table[entry].name]);
#endif
					if (!strcmp((const char *)rel->symbol_name, (const char *)&temp_string_table[temp_symbol_table[entry].name_offset]) &&
					    temp_symbol_table[entry].sHeaderIndex != section_index_undefined &&
					    ELF_S_BIND(temp_symbol_table[entry].info) == symbol_binding_global)
					{
						// We found a symbol whose name matches what we want to need, it's section index is not undefined and it's globally bound
						if (found_symbol == NULL)
						{
							found_symbol = &temp_symbol_table[entry];
							rel->symbol.info = found_symbol->info;
							break;
						}
						else
						{
							// We found the symbol again in a different file. Can this happen?
							goto NEXT_REL;
						}
					}
				}

				// TODO: check if it's possible to hit the else case above. If not, a if (found_symbol != NULL) break; should speed things up here.

				temp_file_table = temp_file_table->succ;
			}
		}

		// if it is still notype then check enclave functions
		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype && _enclave_fct_table != NULL)
		{
			for (uint64_t entry = 0; entry < _enclave_fct_counter; ++entry)
			{
				if (strcmp((const char*)rel->symbol_name, _enclave_fct_table[entry].fct_name) != 0)
				{
					continue;
				}
				// Found enclave functions
				rel->symbol.info = ELF_S_INFO(symbol_binding_global, symbol_type_enclave);
				rel->ref.encl_fct = &_enclave_fct_table[entry];
				rel->resolved = 1;
				changes++;
				goto NEXT_REL;
			}
		}

		// if it is STILL notype, then we can just skip the rest
		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype)
		{
			goto NEXT_REL;
		}

		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
		{
			if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
			{
				_pa_obj_table_t *obj = _pa_find_obj_by_name((char *)rel->symbol_name, fct->version, fct->file_table_entry->_local_obj_table);

				if (obj != NULL)
				{
					rel->ref.obj = obj;
					rel->resolved = 1;
					changes++;
					goto NEXT_REL;
				}

				// Did not find, could not resolve
				goto NEXT_REL;
			} // END IF symbol binding is local
			else
			{
				_pa_obj_table_t *obj = _pa_find_obj_by_name((char *)rel->symbol_name, fct->version, _obj_table);

				if (obj != NULL)
				{
					// Found global object
					rel->ref.obj = obj;
					rel->resolved = 1;
					changes++;
					goto NEXT_REL;
				}

				// Did not find, could not resolve
				goto NEXT_REL;
			} // END IF symbol binding is global
		} // END IF symbol type is object
		else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
		{
			_pa_fct_table_t *it = _fct_table;
			if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
			{
				it = fct->file_table_entry->_fct_table;
			}

			rel->ref.fct = _pa_find_sym_by_name((char *)rel->symbol_name, it);
			if (rel->ref.fct != NULL)
			{
				// Found local or lobal function
				rel->resolved = 1;
				changes += _pa_add_parent_relocation(rel->ref.fct, fct, rel);
				goto NEXT_REL;
			}
		}
		else
		{
			// wrong relocation type!
		}

		NEXT_REL:;
		// Next relocation
	}

	return changes;
}

static uint64_t _pa_resolve_obj_relocations(_pa_obj_table_t *_obj)
{
	uint64_t changes = 0;
	for (uint64_t i = 0; i < _obj->relocation_entries; ++i)
	{
		_pa_relocation_t *rel = _obj->resolved_relocations + i;
		if (rel->resolved)
		{
			continue;
		}

		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype)
		{
			char *temp_string_table = NULL;
			_pa_file_table_t *temp_file_table = _file_table;
			elf_symbol_t *temp_symbol_table = NULL;
			elf_symbol_t *found_symbol = NULL;
			// This loop iterates through all added files to find the needed symbol in their symbol table
			while (temp_file_table != NULL)
			{
				temp_symbol_table = temp_file_table->symbol_table;
				temp_string_table = temp_file_table->string_table;

				for (int entry = 0; entry < temp_file_table->symbol_table_entries; entry++)
				{
#ifdef DEBUG_PA_LOAD_FCT_EX_GLOBAL_SYMBOL
					debug_print_elf_symbol(&temp_symbol_table[entry],&temp_string_table[temp_symbol_table[entry].name]);
#endif
					if (!strcmp((const char *)rel->symbol_name, (const char *)&temp_string_table[temp_symbol_table[entry].name_offset]) &&
					    temp_symbol_table[entry].sHeaderIndex != section_index_undefined &&
					    ELF_S_BIND(temp_symbol_table[entry].info) == symbol_binding_global)
					{
						// We found a symbol whose name matches what we want to need, it's section index is not undefined and it's globally bound
						if (found_symbol == NULL)
						{
							found_symbol = &temp_symbol_table[entry];
							rel->symbol.info = found_symbol->info;
							break;
						}
						else
						{
							// We found the symbol again in a different file. Can this happen?
							goto NEXT_REL;
						}
					}
				}

				// TODO: check if it's possible to hit the else case above. If not, a if (found_symbol != NULL) break; should speed things up here.

				temp_file_table = temp_file_table->succ;
			}
		}

		// if it is still notype then check enclave functions
		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype && _enclave_fct_table != NULL)
		{
			for (uint64_t entry = 0; entry < _enclave_fct_counter; ++entry)
			{
				if (strcmp((const char*)rel->symbol_name, _enclave_fct_table[entry].fct_name) != 0)
				{
					continue;
				}
				// Found enclave functions
				rel->symbol.info = ELF_S_INFO(symbol_binding_global, symbol_type_enclave);
				rel->ref.encl_fct = &_enclave_fct_table[entry];
				rel->resolved = 1;
				changes++;
				goto NEXT_REL;
			}
		}

		// if it is STILL notype, then we can just skip the rest
		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_notype)
		{
			goto NEXT_REL;
		}

		if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
		{
			if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
			{
				_pa_obj_table_t *obj = _pa_find_obj_by_name((char *)rel->symbol_name, 0, _obj->file->_local_obj_table);

				if (obj != NULL)
				{
					rel->ref.obj = obj;
					rel->resolved = 1;
					changes++;
					goto NEXT_REL;
				}

				// Did not find, could not resolve
				goto NEXT_REL;
			} // END IF symbol binding is local
			else
			{
				_pa_obj_table_t *obj = _pa_find_obj_by_name((char *)rel->symbol_name, 0, _obj_table);

				if (obj != NULL)
				{
					// Found global object
					rel->ref.obj = obj;
					rel->resolved = 1;
					changes++;
					goto NEXT_REL;
				}
				// Did not find, could not resolve
				goto NEXT_REL;
			} // END IF symbol binding is global
		} // END IF symbol type is object
		else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
		{
			_pa_fct_table_t *it = _fct_table;
			if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
			{
				it = _obj->file->_fct_table;
			}

			rel->ref.fct = _pa_find_sym_by_name((char *)rel->symbol_name, it);
			if (rel->ref.fct != NULL)
			{
				// Found local or lobal function
				rel->resolved = 1;
				// FIXME: parent relocation need also to exist for objects
				//changes += _pa_add_parent_relocation(rel->ref.fct, fct, rel);
				goto NEXT_REL;
			}
		}
		else
		{
			// wrong relocation type!
		}

		NEXT_REL:;
		// Next relocation
	}

	return changes;
}

static uint64_t _pa_add_parent_relocation(_pa_fct_table_t *child, _pa_fct_table_t *parent, _pa_relocation_t *parent_relocation)
{
	// Try to find parent relocation in child
	_pa_parent_relocation_t *it = child->parent_relocations;
	while(it != NULL)
	{
		if (it->rel == parent_relocation)
		{
			// Found, don't need to add.
			return 0;
		}
		it = it->next;
	}

	// Add to front of list
	_pa_parent_relocation_t *elem = (_pa_parent_relocation_t *)malloc(sizeof(_pa_parent_relocation_t));
	if (elem == NULL)
	{
		// malloc error
		abort();
	}

	elem->next = child->parent_relocations;
	elem->rel = parent_relocation;
	elem->parent = parent;
	child->parent_relocations = elem;
	return 1;
}

static uint64_t _pa_add_all_indirect_dependencies(_pa_fct_table_t *child, _pa_fct_table_t *parent)
{
	uint64_t changes = 0;
	if (child == NULL)
	{
		return changes;
	}

	_pa_parent_relocation_t *pit;
	if (parent == NULL)
	{
		pit = child->parent_relocations;
		child->status |= _pa_fct_deps_adding;
	}
	else
	{
		if (_PA_FCT_IS_DEPS_ADDING(parent->status))
		{
			return changes;
		}
		pit = parent->parent_relocations;
		parent->status |= _pa_fct_deps_adding;
	}

	// Go through all direct parents of this child
	while (pit != NULL)
	{
		// Add this child to the direct parent as an indirect dependency.
		changes += _pa_add_to_indirect_dependencies(pit->parent, child);
		// Now, also add this child as an indirect dependency to all the parents of this parent
		if (pit->parent->parent_relocations != NULL)
		{
			changes += _pa_add_all_indirect_dependencies(child, pit->parent);
		}

		pit = pit->next;
	}

	if (parent == NULL)
		child->status &= _pa_fct_no_deps_adding;
	else
		parent->status &= _pa_fct_no_deps_adding;

	return changes;
}

static uint64_t _pa_add_to_indirect_dependencies(_pa_fct_table_t *parent, _pa_fct_table_t *child)
{
	if (parent == NULL || child == NULL)
	{
		return 0;
	}

	_pa_indirect_dependency_t *it = parent->indirect_dependencies;
	while (it != NULL)
	{
		if (it->fct == child)
		{
			// Already present.
			return 0;
		}
		it = it->next;
	}

	// Add at front
	_pa_indirect_dependency_t *elem = malloc(sizeof(_pa_indirect_dependency_t));
	if (elem == NULL)
	{
		abort();
	}
	elem->next = parent->indirect_dependencies;
	elem->fct = child;

	parent->indirect_dependencies = elem;

	return 1;
};

/**
 * @brief Adds a function to be dynamically loaded. Can also add files without functions if setting @p fct_name to NULL.
 * @param fct_id
 * @param fct_name
 * @param file_id
 * @param file_ptr
 * @return
 */
dl_status_t dl_add_fct(const char *fct_name, dl_file_handle_t file_handle)
{
	write_lock(&table_lock);

	_pa_fct_table_t *fct = NULL;
	dl_status_t status = _pa_add_fct_ex(file_handle, fct_name, &_fct_table, &fct);
	if (status == DL_SUCCESS)
	{
		function_counter++;
		fct->edge_fct = true;
	}

	write_unlock(&table_lock);
	return status;
}

dl_status_t dl_add_fct_arr(dl_fct_t *fcts, size_t num_fcts)
{
	if (fcts == NULL || num_fcts == 0)
	{
		return DL_SUCCESS;
	}

	write_lock(&table_lock);

	dl_status_t ret = DL_SUCCESS;

	for (size_t i = 0; i < num_fcts; ++i)
	{
		uint64_t id = _dl_gen_rand_in_range(0, num_fcts - 1);
		while (fcts[id].file_handle == DL_EMPTY_HANDLE)
		{
			++id;
			if (id >= num_fcts)
			{
				id = 0;
			}
		}

		_pa_fct_table_t *fct = NULL;
		ret = _pa_add_fct_ex(fcts[id].file_handle, fcts[id].name, &_fct_table, &fct);
		if (ret != DL_SUCCESS)
		{
			write_unlock(&table_lock);
			return ret;
		}
		function_counter++;
		fct->edge_fct = true;
		fcts[id].file_handle = DL_EMPTY_HANDLE;
	}

	write_unlock(&table_lock);
	return ret;
}

/**
 * @brief Deletes the contents of a _pa_fct_table_t function object. Does not delete the object itself!
 * @param fct
 * @return
 */
static dl_status_t _pa_del_fct_obj(_pa_fct_table_t *fct)
{
	if (_PA_FCT_IS_LOADED(fct->status))
	{
		//Free opcode memory
		dl_status_t status = _pa_free(fct->addr);
		if (status != DL_SUCCESS)
		{
			return status;
		}

		_pa_remove_lru_table(fct->lru_entry);
		free(fct->lru_entry);
	}

	ocall_free(fct->sealed_opcode);

	// remove references to this function in other functions
	_pa_fct_table_t *it = _fct_table;
	while (it != NULL)
	{
		for (uint64_t i = 0; i < it->relocation_entries; ++i)
		{
			if (it->resolved_relocations[i].resolved == 1 && it->resolved_relocations[i].ref.fct == fct)
			{
				// unresolve relocation
				it->resolved_relocations[i].resolved = 0;
				it->resolved_relocations[i].ref.fct = NULL;
			}
		}

		_pa_parent_relocation_t *pit = it->parent_relocations;
		_pa_parent_relocation_t *prev = NULL;
		while (pit != NULL)
		{
			if (pit->parent != fct)
			{
				prev = pit;
				pit = pit->next;
				continue;
			}

			if (pit == it->parent_relocations)
			{
				// was at the start
				it->parent_relocations = pit->next;
				free(pit);
				pit = it->parent_relocations;
			}
			else
			{
				prev->next = pit->next;
				free(pit);
				pit = prev->next;
			}
		}

		_pa_indirect_dependency_t *dit = it->indirect_dependencies;
		_pa_indirect_dependency_t *dprev = NULL;
		while (dit != NULL)
		{
			if (dit->fct != fct)
			{
				dprev = dit;
				dit = dit->next;
				continue;
			}

			if (dit == it->indirect_dependencies)
			{
				// was at the start
				it->indirect_dependencies = dit->next;
				free(dit);
				dit = it->indirect_dependencies;
			}
			else
			{
				dprev->next = dit->next;
				free(dit);
				dit = dprev->next;
			}
		}

		it = it->succ;
	}

	_pa_file_table_t *fit = _file_table;
	while (fit != NULL)
	{
		it = fit->_fct_table;

		while (it != NULL)
		{
			for (uint64_t i = 0; i < it->relocation_entries; ++i)
			{
				if (it->resolved_relocations[i].resolved == 1 && it->resolved_relocations[i].ref.fct == fct)
				{
					// unresolve relocation
					it->resolved_relocations[i].resolved = 0;
					it->resolved_relocations[i].ref.fct = NULL;
				}
			}

			_pa_parent_relocation_t *pit = it->parent_relocations;
			_pa_parent_relocation_t *prev = NULL;
			while (pit != NULL)
			{
				if (pit->parent != fct)
				{
					prev = pit;
					pit = pit->next;
					continue;
				}

				if (pit == it->parent_relocations)
				{
					// was at the start
					it->parent_relocations = pit->next;
					free(pit);
					pit = it->parent_relocations;
				}
				else
				{
					prev->next = pit->next;
					free(pit);
					pit = prev->next;
				}
			}

			_pa_indirect_dependency_t *dit = it->indirect_dependencies;
			_pa_indirect_dependency_t *dprev = NULL;
			while (dit != NULL)
			{
				if (dit->fct != fct)
				{
					dprev = dit;
					dit = dit->next;
					continue;
				}

				if (dit == it->indirect_dependencies)
				{
					// was at the start
					it->indirect_dependencies = dit->next;
					free(dit);
					dit = it->indirect_dependencies;
				}
				else
				{
					dprev->next = dit->next;
					free(dit);
					dit = dprev->next;
				}
			}

			it = it->succ;
		}

		fit = fit->succ;
	}

	free(fct->resolved_relocations);
	_pa_parent_relocation_t *pit = fct->parent_relocations;
	while (pit != NULL)
	{
		_pa_parent_relocation_t *next = pit->next;
		free(pit);
		pit = next;
	}

	_pa_indirect_dependency_t *dit = fct->indirect_dependencies;
	while (dit != NULL)
	{
		_pa_indirect_dependency_t *next = dit->next;
		free(dit);
		dit = next;
	}

	return DL_SUCCESS;
}

static dl_status_t _dl_del_fct(const char *fct_name, _pa_fct_table_t **table)
{
	dl_status_t status = DL_SUCCESS;

	if (*table == NULL)
	{
		status = PA_EMPTY_FUNCTION_TABLE;
		goto END;
	}

	_pa_fct_table_t *localptr = _pa_find_sym_by_name(fct_name, *table);

	if (localptr == NULL)
	{
		status = PA_FUNCTION_NOT_FOUND;
		goto END;
	}

	if (localptr->calls_in_progress != 0)
	{
		// Cannot delete function, it has non-zero calls in progress
		status = PA_FUNCTION_BLOCKED;
		goto END;
	}

	if ((status = _pa_del_fct_obj(localptr)) != DL_SUCCESS)
	{
		goto END;
	}


	if (localptr->pred == NULL && localptr->succ == NULL)
	{
		*table = NULL;
#ifdef __PA_FAST_IDS
		if (id < __PA_FAST_IDS)
		{
			_fct_array[id] = NULL;
		}
#endif
		free(localptr);
	}
	else if (localptr->pred == NULL && localptr->succ != NULL)
	{
		*table = localptr->succ;
		(*table)->pred = NULL;
#ifdef __PA_FAST_IDS
		if (id < __PA_FAST_IDS)
		{
			_fct_array[id] = NULL;
		}
#endif
		free(localptr);
	}
	else if (localptr->pred != NULL && localptr->succ != NULL)
	{
		localptr->pred->succ = localptr->succ;
		localptr->succ->pred = localptr->pred;
#ifdef __PA_FAST_IDS
		if (id < __PA_FAST_IDS)
		{
			_fct_array[id] = NULL;
		}
#endif
		free(localptr);
	}
	else if (localptr->pred != NULL && localptr->succ == NULL)
	{
		localptr->pred->succ = NULL;
#ifdef __PA_FAST_IDS
		if (id < __PA_FAST_IDS)
		{
			_fct_array[id] = NULL;
		}
#endif
		free(localptr);
	}
	else
	{
		status = PA_UNKNOWN_ERROR;
		goto END;
	}

	END:
	return status;
}

dl_status_t dl_del_fct(const char *fct_name)
{
	write_lock(&table_lock);
	dl_status_t status = _dl_del_fct(fct_name, &_fct_table);
	write_unlock(&table_lock);
	return status;
}

dl_status_t dl_destroy(void)
{
	write_lock(&table_lock);

	if (_fct_table == NULL && _file_table == NULL && _enclave_fct_table == NULL)
	{
		write_unlock(&table_lock);
		return PA_EMPTY_FUNCTION_TABLE;
	}

	if (_enclave_fct_table != NULL)
	{
		for (int i = 0; i < _enclave_fct_counter; i++)
		{
			free(_enclave_fct_table[i].fct_name);
		}

		free(_enclave_fct_table);
		_enclave_fct_table = NULL;
		_enclave_fct_counter = 0;
	}

	_pa_fct_table_t *fct_ptr = _fct_table;
	if (_fct_table != NULL)
	{
		_fct_table = NULL;
		while (fct_ptr != NULL)
		{
			_pa_del_fct_obj(fct_ptr);

			_pa_fct_table_t *pred = fct_ptr->pred;
			fct_ptr = fct_ptr->succ;
			free(pred);
		}
	}

	_pa_obj_table_t *obj_ptr = _obj_table;
	if (_obj_table != NULL)
	{
		_obj_table = NULL;
		while (obj_ptr->succ != NULL)
		{
			_pa_free(obj_ptr->addr);
			obj_ptr = obj_ptr->succ;
			free(obj_ptr->pred);
		}
		_pa_free(obj_ptr->addr);
		free(obj_ptr);
	}

	if (_file_table != NULL)
	{
		_pa_file_table_t *file_ptr = _file_table;
		_file_table = NULL;

		while (file_ptr != NULL)
		{
			if (file_ptr->_local_obj_table != NULL)
			{
				obj_ptr = file_ptr->_local_obj_table;
				while (obj_ptr->succ != NULL)
				{
					_pa_free(obj_ptr->addr);
					obj_ptr = obj_ptr->succ;
					free(obj_ptr->pred);
				}
				_pa_free(obj_ptr->addr);
				free(obj_ptr);
			}

			if (file_ptr->_fct_table != NULL)
			{
				fct_ptr = file_ptr->_fct_table;
				while (fct_ptr != NULL)
				{
					_pa_del_fct_obj(fct_ptr);

					_pa_fct_table_t *pred = fct_ptr->pred;
					fct_ptr = fct_ptr->succ;
					free(pred);
				}
			}
			_pa_file_table_t *pred = file_ptr->pred;
			file_ptr = file_ptr->succ;
			free(pred);
		}
	}

	if (_lru_first != NULL)
	{
		_pa_fct_lru_table_t *lit = _lru_first;
		_lru_first = NULL;
		_lru_last = NULL;
		while (lit->succ != NULL)
		{
			lit = lit->succ;
			free(lit->pred);
		}
		free(lit);
	}

	function_counter = 0;

	write_unlock(&table_lock);
	return DL_SUCCESS;
}

static dl_status_t _pa_find_func_memory(_pa_fct_table_t *fct)
{
	dl_status_t status = DL_SUCCESS;
	if ((status = _pa_malloc_code(&fct->addr, fct->opcode_size)) != DL_SUCCESS)
	{
		if (status == PA_MEMORY_NO_FREE_SPACE_FOUND)
		{
			// No free space, have to swap some function out

			size_t wanted_size = fct->opcode_size;
			_pa_mem_ctl_t *mem_ctl_ptr, *found_mem_ctl_ptr = NULL;

			read_lock(&lru_lock);

			_pa_fct_lru_table_t *lru_ptr = _lru_first, *found_lru_ptr = NULL;

			while (lru_ptr != NULL)
			{
				if (lru_ptr->fct->calls_in_progress == 0)
				{
					mem_ctl_ptr = lru_ptr->fct->addr - sizeof(_pa_mem_ctl_t);

					if (mem_ctl_ptr->size == wanted_size)
					{
						found_lru_ptr = lru_ptr;
						break;
					}
					else if (mem_ctl_ptr->size > wanted_size && (found_mem_ctl_ptr == NULL || mem_ctl_ptr->size < found_mem_ctl_ptr->size))
					{
						found_mem_ctl_ptr = mem_ctl_ptr;
						found_lru_ptr = lru_ptr;
					}
				}

				lru_ptr = lru_ptr->succ;
			}

			if (found_lru_ptr != NULL)
			{
				// We found a suitable memory location
#ifdef DEBUG
				debug_print_fct_table_t(found_lru_ptr->fct);
#endif
				if ((status = _pa_unload_fct_ex(found_lru_ptr->fct)) != DL_SUCCESS)
				{
					goto END;
				}

				if ((status = _pa_malloc_code(&fct->addr, wanted_size)) != DL_SUCCESS)
				{
					goto END;
				}

				goto END;
			}

#ifndef __PA_ASSUME_ALL_LOADED
			// We did not find a suitable memory location.
			// We will kick out functions until there is enough memory
			lru_ptr = _lru_first;

			while (lru_ptr != NULL)
			{
#ifdef DEBUG
				debug_print_lru_table_t(lru_ptr);
#endif
				if (lru_ptr->fct->calls_in_progress == 0)
				{
					found_lru_ptr = lru_ptr;
					lru_ptr = lru_ptr->succ;

					if ((status = _pa_unload_fct_ex(found_lru_ptr->fct)) != DL_SUCCESS)
					{
						goto END;
					}

					if ((status = _pa_malloc_code(&fct->addr, wanted_size)) == DL_SUCCESS)
					{
						goto END;
					}
					else if (status == PA_MEMORY_NO_FREE_SPACE_FOUND)
					{
						continue;
					}
					else
					{
						goto END;
					}
				}
				else
				{
					lru_ptr = lru_ptr->succ;
				}
			}
#endif

			status = PA_MEMORY_NO_FREE_SPACE_FOUND;

			END:
			read_unlock(&lru_lock);
		}
	}
	return status;
}

/**
 * @brief This function loads a function and all its dependencies into memory. You will need to hold a write lock on table_lock.
 * @param fct_table_ptr
 * @return
 */
dl_status_t _pa_load_fct_ex(_pa_fct_table_t *fct_table_ptr)
{
	if (fct_table_ptr == NULL)
	{
		return PA_EMPTY_FUNCTION_TABLE;
	}

	_pa_fct_table_t *fct_ptr = fct_table_ptr;
	dl_status_t status;
	dl_status_t retval = DL_SUCCESS;

	if (_PA_FCT_IS_LOADED(fct_ptr->status))
	{
		status = _pa_load_dependencies(fct_ptr);
		return status;
	}

	//Allocate some space for opcode
	status = _pa_find_func_memory(fct_ptr);
	if (status != DL_SUCCESS)
	{
		return status;
	}

	// Unseal opcode
	sgx_sealed_data_t *sealed_data = malloc(fct_ptr->sealed_size);
	memcpy(sealed_data, fct_ptr->sealed_opcode, fct_ptr->sealed_size);
	uint32_t size = fct_ptr->opcode_size;
	sgx_status_t ret = sgx_unseal_data(sealed_data, NULL, 0, fct_ptr->addr, &size);
	if (ret != SGX_SUCCESS)
	{
		_pa_free(fct_ptr->addr);
		free(sealed_data);
		fct_ptr->addr = NULL;
		return DL_SEAL_FAILED;
	}
	free(sealed_data);
	if (size != fct_ptr->opcode_size)
	{
		// decrpyted size does not match the functioon size, possible rollback attack?
		_pa_free(fct_ptr->addr);
		fct_ptr->addr = NULL;
		return DL_HASH_FAILED;
	}
	// Check hash, this is not redundant even though the sealing routine checks a MAC!
	// To prevent rollback attacks, we have to check if the hash we get actually matches what we expect.
	sgx_sha256_hash_t hash;
	ret = sgx_sha256_msg(fct_ptr->addr, fct_ptr->opcode_size, &hash);
	if (ret != SGX_SUCCESS)
	{
		_pa_free(fct_ptr->addr);
		fct_ptr->addr = NULL;
		return DL_HASH_FAILED;
	}
	if ((memcmp(hash, fct_ptr->opcode_hash, sizeof(sgx_sha256_hash_t))) != 0)
	{
		_pa_free(fct_ptr->addr);

		fct_ptr->addr = NULL;
		return PA_HASH_MISMATCH;
	}

	fct_ptr->status |= _pa_fct_is_loading;

	// If there are relocation entries, we have to resolve them
	if (fct_ptr->resolved_relocations != NULL)
	{
		// This loop iterates through the rela section of the file the symbol that needs to be loaded is located in
		for (int i = 0; i < fct_ptr->relocation_entries; i++)
		{
			_pa_relocation_t *rel = &fct_ptr->resolved_relocations[i];
#ifdef DEBUG
			//debug_print_elf_relocation(&relocations[i]);
			//debug_print_elf_symbol(symbol,symbol_name);
#endif
			if (!rel->resolved)
			{
				//__asm__("ud2");
				snprintf(_dl_error_msg, sizeof(_dl_error_msg) - 1, "Unresolved relocation while loading %s: >%s< unresolved", fct_ptr->fct_name, rel->symbol_name);
				retval = PA_UNRESOLVED_RELOCATION;
				goto ERROR;
			}

			if (ELF_S_BIND(rel->symbol.info) == symbol_binding_global)
			{

#ifdef DEBUG
				//temp_string_table = found_file_table->string_table;//((void*)found_file_table->file_header) + found_file_table->section_header[found_file_table->symbol_table->link].offset;
				//debug_print("Symbol found:");
				//debug_print_elf_symbol(found_symbol, (char *)&temp_string_table[found_symbol->name_offset]);
#endif
				// At this point we found the global symbol that we need for our relocation
				// found_symbol contains the needed symbol
				// found_file_table the file it has been found in
				// Now we need to check the kind of relocation
				if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
				{
					// Needed symbol is an global object.

					// At this point temp_obj holds the found object
					status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
				{
					// The needed symbol is a function.

					_pa_fct_table_t *temp_fct = rel->ref.fct;

					// We found the symbol
					if (!_PA_FCT_IS_LOADED(temp_fct->status) && !_PA_FCT_IS_LOADING(temp_fct->status))
					{
						// The needed symbol is neither currently loaded nor currently in the process of being loaded. We need to load it.
						status = _pa_load_fct_ex(temp_fct);

						// The needed symbol is now loaded.
						if (status != DL_SUCCESS)
						{
							retval = status;
							goto ERROR;
						}
					}
					else if (_PA_FCT_IS_LOADED(temp_fct->status))
					{
						// The needed symbol is loaded so we need to look at the subcalls of the needed symbol

						_pa_update_lru_table(temp_fct->lru_entry);

						status = _pa_load_dependencies(temp_fct);

						if (status != DL_SUCCESS)
						{
							retval = status;
							goto ERROR;
						}
					}

					// Do the actual relocation
					status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &temp_fct->addr, 0);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_enclave)
				{
					if ((status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &rel->ref.encl_fct->addr, 0)) != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else // needed global symbol is neither function nor object
				{
					retval = PA_UNSUPPORTED_SYMBOL_TYPE;
					goto ERROR;
				}
			} // global symbol end
			else if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
			{
				if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
				{
					// Needed local symbol is an local object

					status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->symbol.value + rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
				{
					// Needed local symbol is a function

					_pa_fct_table_t *temp_fct = NULL;

					// Iterate over all symbols of the file
					temp_fct = rel->ref.fct;

					if (!_PA_FCT_IS_LOADED(temp_fct->status) && !_PA_FCT_IS_LOADING(temp_fct->status))
					{
						// If the needed local symbol is neither loaded nor currently in the process of being loaded we need to load it

						status = _pa_load_fct_ex(temp_fct);
						if (status != DL_SUCCESS)
						{
							retval = status;
							goto ERROR;
						}
					}
					else if (_PA_FCT_IS_LOADED(temp_fct->status))
					{
						// Needed local symbol is loaded

						_pa_update_lru_table(temp_fct->lru_entry);

						status = _pa_load_dependencies(temp_fct);
						if (status != DL_SUCCESS)
						{
							retval = status;
							goto ERROR;
						}
					}
#ifdef DEBUG
					debug_print_fct_table_t(temp_fct);
#endif
					// We can now do our relocation
					status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &temp_fct->addr, 0);
					if (status != DL_SUCCESS)
					{
						retval = status;
						goto ERROR;
					}
				}
				else
				{
					retval = PA_UNSUPPORTED_SYMBOL_TYPE;
					goto ERROR;
				}
			} // local symbol end
			else
			{
				// It is neither a local nor global symbol, we cannot work with that
				retval = PA_UNSUPPORTED_SYMBOL_BINDING;
				goto ERROR;
			}
		}

	} // Done resolving relocations

	if (fct_ptr->lru_entry == NULL)
	{
		if ((fct_ptr->lru_entry = malloc(sizeof(_pa_fct_lru_table_t))) == NULL)
		{
			abort();
		}

		fct_ptr->lru_entry->fct = fct_ptr;
		fct_ptr->lru_entry->pred = NULL;
		fct_ptr->lru_entry->succ = NULL;

		_pa_update_lru_table(fct_ptr->lru_entry);
	}

	// Check if the loaded function has callers
	if (fct_ptr->parent_relocations != NULL)
	{
		_pa_parent_relocation_t *it = fct_ptr->parent_relocations;
		while (it != NULL)
		{
			if (_PA_FCT_IS_LOADED(it->parent->status))
			{
				_pa_relocation(ELF_R_TYPE(it->rel->elfrel.info), it->rel->elfrel.addend, it->parent->addr + it->rel->elfrel.offset, &it->rel->ref.fct->addr, 0);
			}
			it = it->next;
		}
	}

	// Make memory executable


	fct_ptr->status &= _pa_fct_is_not_loading;
	fct_ptr->status |= _pa_fct_loaded;

	return DL_SUCCESS;

	ERROR:
	status = _pa_free(fct_ptr->addr);

	if (status != DL_SUCCESS)
	{
		return status;
	}

	fct_ptr->addr = NULL;
	fct_ptr->status &= _pa_fct_is_not_loading;
	return retval;
}

static dl_status_t _pa_load_dependencies(_pa_fct_table_t *fct)
{
	dl_status_t status = DL_SUCCESS;

	_pa_indirect_dependency_t *dep = fct->indirect_dependencies;
	while (dep != NULL)
	{
		if (fct == dep->fct)
		{
			// We don't need to load ourselves
			dep = dep->next;
			continue;
		}
		if (!_PA_FCT_IS_LOADED(dep->fct->status) && !_PA_FCT_IS_LOADING(dep->fct->status))
		{
			status = _pa_load_fct_ex(dep->fct);
			if (status != DL_SUCCESS)
			{
				goto END;
			}
		}
		dep = dep->next;
	}

	END:
	return status;
}

dl_status_t dl_load_fct(const char* fct_name)
{
	dl_status_t ret;
	write_lock(&table_lock);

	_pa_fct_table_t *fct_ptr = _pa_find_sym_by_name(fct_name, _fct_table);

	if (fct_ptr == NULL)
	{
		ret = PA_FUNCTION_NOT_FOUND;
		goto END;
	}

	ret = _pa_load_fct_ex(fct_ptr);

	END:
	write_unlock(&table_lock);
	return ret;
}

/**
 * @brief Add the object named @p name into the object table @p obj_table_ptr and returns the added object in @p ptr.
 * @param name
 * @param obj_table_ptr
 * @param ptr
 * @return
 */
static dl_status_t _pa_add_obj(const char *name, dl_file_handle_t file_handle, _pa_obj_table_t **obj_table_ptr, _pa_obj_table_t **ptr)
{
	if (name == NULL || obj_table_ptr == NULL || ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	if ((strlen(name) + 1) > PA_MAX_OBJ_NAME_LENGTH)
	{
		return PA_OBJ_NAME_TOO_LONG;
	}

	_pa_file_table_t *file_entry = _file_table;
	while (file_entry != NULL)
	{
		if (file_entry->id == file_handle)
		{
			break;
		}

		file_entry = file_entry->succ;
	}
	if (file_entry == NULL)
	{
		return PA_INVALID_FILE_ID;
	}

	if (*obj_table_ptr == NULL)
	{
		*obj_table_ptr = malloc(sizeof(_pa_obj_table_t));
		if (*obj_table_ptr == NULL)
		{
			abort();
		}

		(*obj_table_ptr)->succ = NULL;
		(*obj_table_ptr)->pred = NULL;
		(*obj_table_ptr)->addr = NULL;
		(*obj_table_ptr)->alignment_offset = 0;
		(*obj_table_ptr)->alignment = 0;
		(*obj_table_ptr)->version = 0;
		(*obj_table_ptr)->resolved_relocations = NULL;
		(*obj_table_ptr)->relocation_entries = 0;
		(*obj_table_ptr)->file = file_entry;
		memcpy((*obj_table_ptr)->name, name, strlen(name) + 1);
		*ptr = (*obj_table_ptr);
	}
	else
	{
		_pa_obj_table_t *local_obj = (*obj_table_ptr);
		while (local_obj->succ != NULL)
		{
			local_obj = local_obj->succ;
		}

		local_obj->succ = malloc(sizeof(_pa_obj_table_t));
		if (local_obj->succ == NULL)
		{
			abort();
		}

		local_obj->succ->pred = local_obj;
		local_obj->succ->succ = NULL;
		local_obj->succ->addr = NULL;
		local_obj->succ->alignment_offset = 0;
		local_obj->succ->alignment = 0;
		local_obj->succ->version = 0;
		local_obj->succ->resolved_relocations = NULL;
		local_obj->succ->relocation_entries = 0;
		local_obj->succ->file = file_entry;
		memcpy(local_obj->succ->name, name, strlen(name) + 1);
		*ptr = local_obj->succ;
	}

	char *rela_section_name;
	if ((rela_section_name = malloc(strlen(PREFIX_RELA) + strlen(PREFIX_DATA) + strlen((const char *) name) + 1)) == NULL)
	{
		abort();
	}

	elf_header_t *elf_header = (elf_header_t *)(file_entry->elf_header);
	elf_section_header_t *section_headers = (void *)elf_header + elf_header->section_header_offset;

	memcpy(rela_section_name, PREFIX_RELA, strlen(PREFIX_RELA));
	memcpy(rela_section_name + strlen(PREFIX_RELA), PREFIX_DATA, strlen(PREFIX_DATA));
	memcpy(rela_section_name + strlen(PREFIX_RELA) + strlen(PREFIX_DATA), name, strlen((const char *) name) + 1);

	int64_t rela_section_index = -1;

	for (unsigned int i = 0; (i < elf_header->sectionHeaderCount) && (rela_section_index == -1); i++)
	{
		if (!strcmp(rela_section_name, (const char *) &file_entry->section_header_string_table[section_headers[i].name_offset]))
		{
			rela_section_index = i;
		}
	}

	free(rela_section_name);

	if (rela_section_index != -1)
	{
		dl_status_t status;
		if ((status = _pa_copy_obj_relocations(*ptr, elf_header, rela_section_index)) != DL_SUCCESS)
		{
			return status;
		}
	}

	//while (_pa_resolve_all_relocations() != 0);

	return DL_SUCCESS;
}

/**
 * @brief Searches for an object named @p name in the object table @p table
 * @param name
 * @param table
 * @return
 */
static inline _pa_obj_table_t *_pa_find_obj_by_name(const char *name, uint16_t version, _pa_obj_table_t *table)
{
	_pa_obj_table_t *obj = NULL;

	while (table != NULL)
	{
		if (!strncmp(name, (const char *) table->name, PA_MAX_OBJ_NAME_LENGTH))
		{
			if (table->version < version)
			{
				// we might find a better fitting one later
				obj = table;
			}
			else if (table->version == version)
			{
				obj = table;
				// we found the perfect one
				break;
			}
			// else: table->version > version
			// this is not the one we need, ignore it.
		}
		table = table->succ;
	}

	return obj;
}

/**
 * @brief Searches for an function named @p name in the function table @p table
 * @param name
 * @param table
 * @return
 */
static inline _pa_fct_table_t *_pa_find_sym_by_name(const char *name, _pa_fct_table_t *table)
{
	while (table != NULL)
	{
		if (!strncmp(name, (const char *) table->fct_name, PA_MAX_FCT_NAME_LENGTH))
		{
			break;
		}
		table = table->succ;
	}

	return table;
}

/**
 * @brief Searches for an function with id @p id in the function table @p table
 * @param name
 * @param table
 * @return
 */
static inline _pa_fct_table_t *_pa_find_sym_by_id(dl_fct_id_t id, _pa_fct_table_t *table)
{
	while (table != NULL)
	{
		if (id == table->id)
		{
			break;
		}
		table = table->succ;
	}

	return table;
}

static inline uint64_t __dl_rdtscp()
{
	uint32_t aux;
	uint64_t rax,rdx;
	__asm__ __volatile__ ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (aux) : : );
	return (rdx << 32) + rax;
}

static uint64_t last_call = 0;
#define __MIN_TIME_PASSED 10000
#define __MAX_TIME_PASSED 100000

static dl_status_t __pa_call_ex(const char *fct_name, void **fct_ptr)
{

	// TODO: call cleanup if in dirty state (no cleanup since last add)
#ifdef ASLR_IN_BAND
	/*
	if (last_call == 0)
	{
		last_call = __dl_rdtscp();
	}
	else
	{
		uint64_t now = __dl_rdtscp();
		debug_printf("time passed: %lu\n", now - last_call);
		int do_shuffle = 0;
		if (now < last_call) // we traveled back in time or overflow
		{
			do_shuffle = 1;
		}
		else
		{
			uint64_t diff = now - last_call;
			if (diff <= __MIN_TIME_PASSED || diff >= __MAX_TIME_PASSED) // not enough time passed, something is wonky
			{
				do_shuffle = 1;
			}
		}
		if (do_shuffle)
		{
			write_lock(&shuffling_lock);
			dl_status_t ret = _dl_shuffle_fct_addresses();
			if (ret != DL_SUCCESS)
			{
				abort();
			}
			write_unlock(&shuffling_lock);
			goto AFTER_SHUFFLE;
		}
	}
	//*/

	int64_t new_val = __sync_sub_and_fetch(&aslr_current_call_counter, 1);
	if (new_val <= 0)
	{
		write_lock(&shuffling_lock);
		if (aslr_current_call_counter <= 0)
		{
			//debug_printf("shuffling!\n");
			dl_status_t ret = _dl_shuffle_fct_addresses();
			//dl_status_t ret = DL_SUCCESS;
			if (ret != DL_SUCCESS)
			{
				abort();
			}
			aslr_current_call_counter = _dl_gen_rand_in_range(IBASLR_LOWER_BOUND, IBASLR_UPPER_BOUND);
		}
		write_unlock(&shuffling_lock);
	}
	AFTER_SHUFFLE:;
#else
#ifdef ASLR_OUT_BAND
	write_lock(&shuffling_lock);
	if(shuffling_state == 0)
	{
		if(fct_call_cnt_since_last_shuffle >= max_fct_calls_possible_since_last_shuffle)
		{
			write_unlock(&shuffling_lock);
			while (shuffling_state == 0)
			{
				cpu_relax();
			}
			write_lock(&shuffling_lock);
			max_fct_calls_possible_since_last_shuffle = _dl_gen_rand_in_range(500, 1000);
			fct_call_cnt_since_last_shuffle = 0;
		}
		else
		{
			fct_call_cnt_since_last_shuffle += 1;
		}
	}
	else
	{
		fct_call_cnt_since_last_shuffle = 0;
		shuffling_state = max(shuffling_state - 1, 0);
	}
	write_unlock(&shuffling_lock);
#endif
#endif

	unlock_func unlock_table = read_unlock;
	read_lock(&table_lock);

	dl_status_t status = DL_SUCCESS;

	// TODO: Instead of iterating the fct, lets iterate the lru, or maybe some other list?
	// TODO: maybe have a non resetted call counter and create a sorted list for this so that often called functions are always at the front
	_pa_fct_table_t *fct = _pa_find_sym_by_name(fct_name, _fct_table);

	if (unlikely(fct == NULL))
	{
		unlock_table(&table_lock);
		return PA_FUNCTION_NOT_FOUND;
	}

	__sync_fetch_and_add(&fct->calls_in_progress, 1);
	_pa_indirect_dependency_t *dep = NULL;

	if (!_PA_FCT_IS_LOADED(fct->status))
	{
		if (upgrade_trylock(&table_lock))
		{
			status = PA_UPGRADE_LOCK_ERROR;
			goto ERROR_END;
		}

		status = _pa_load_fct_ex(fct);
		unlock_table = write_unlock;

		if (unlikely(status != DL_SUCCESS))
		{
			goto ERROR_END;
		}

		dep = fct->indirect_dependencies;
		while (dep != NULL)
		{
			if (fct == dep->fct)
			{
				// We don't need to load ourselves
				dep = dep->next;
				continue;
			}
			__sync_add_and_fetch(&dep->fct->calls_in_progress, 1);
			dep = dep->next;
		}
	}
	else
	{
		_pa_update_lru_table(fct->lru_entry);

		if (fct->indirect_dependencies == NULL)
		{
			goto EXEC;
		}

		dep = fct->indirect_dependencies;
		while (dep != NULL)
		{
			if (fct == dep->fct)
			{
				// We don't need to load ourselves
				dep = dep->next;
				continue;
			}

			if (!_PA_FCT_IS_LOADED(dep->fct->status) && !_PA_FCT_IS_LOADING(dep->fct->status))
			{
				if (upgrade_trylock(&table_lock))
				{
					status = PA_UPGRADE_LOCK_ERROR;
					goto END;
				}
				unlock_table = write_unlock;
				status = _pa_load_fct_ex(dep->fct);
				if (status != DL_SUCCESS)
				{
					goto END;
				}
			}

			__sync_add_and_fetch(&dep->fct->calls_in_progress, 1);
			dep = dep->next;
		}
	}

	EXEC:;
	*fct_ptr = fct->addr;
	unlock_table(&table_lock);
	return status;


	END:;
	//unlock_table(&table_lock);
	//read_lock(&table_lock);
	_pa_indirect_dependency_t *ndep = fct->indirect_dependencies;
	while (ndep != dep)
	{
		if (fct == ndep->fct)
		{
			// We don't need to load ourselves
			ndep = ndep->next;
			continue;
		}
		__sync_sub_and_fetch(&ndep->fct->calls_in_progress, 1);
		ndep = ndep->next;
	}

	ERROR_END:
	__sync_sub_and_fetch(&fct->calls_in_progress, 1);

	//read_unlock(&table_lock);
	unlock_table(&table_lock);
	return status;
}

dl_status_t dl_call_ex(const char *fct_name, void **retval, void *args)
{
	dl_status_t ret;
	void *fct_ptr = NULL;
	RETRY:;
	ret = __pa_call_ex(fct_name, &fct_ptr);
	if (ret == PA_UPGRADE_LOCK_ERROR)
	{
		goto RETRY;
	}
	if (ret != DL_SUCCESS)
	{
		return ret;
	}

	void *(*_fct_ptr)(void *) = fct_ptr;
	if (retval != NULL)
		*retval = _fct_ptr(args);
	else
		_fct_ptr(args);

	ret = dl_end_call(fct_name);

	return ret;
}

dl_status_t dl_call(const char *fct_name, void *args)
{
	dl_status_t ret;

	void *fct_ptr = NULL;
	RETRY:;
	ret = __pa_call_ex(fct_name, &fct_ptr);
	if (ret == PA_UPGRADE_LOCK_ERROR)
	{
		goto RETRY;
	}
	if (ret != DL_SUCCESS)
	{
		return ret;
	}

	void *(*_fct_ptr)(void *) = fct_ptr;
	_fct_ptr(args);

	ret = dl_end_call(fct_name);

	return ret;
}

dl_status_t dl_start_call(const char* fct_name, void **fct_ptr)
{
	dl_status_t ret;
	RETRY:;
	ret = __pa_call_ex(fct_name, fct_ptr);
	if (ret == PA_UPGRADE_LOCK_ERROR)
	{
		goto RETRY;
	}
	return ret;
}

dl_status_t dl_end_call(const char* fct_name)
{
	dl_status_t ret = DL_SUCCESS;

	read_lock(&table_lock);
	_pa_fct_table_t *fct = _pa_find_sym_by_name(fct_name, _fct_table);

	if (unlikely(fct == NULL))
	{
		read_unlock(&table_lock);
		return PA_FUNCTION_NOT_FOUND;
	}

	_pa_indirect_dependency_t *ndep = fct->indirect_dependencies;
	while (ndep != NULL)
	{
		if (fct == ndep->fct)
		{
			// We don't need to load ourselves
			ndep = ndep->next;
			continue;
		}
		__sync_sub_and_fetch(&ndep->fct->calls_in_progress, 1);
		ndep = ndep->next;
	}

	__sync_sub_and_fetch(&fct->calls_in_progress, 1);

	read_unlock(&table_lock);
	return ret;
}

dl_status_t _pa_unload_fct_ex(_pa_fct_table_t *fct_ptr)
{
	if (_PA_FCT_IS_LOADED(fct_ptr->status))
	{
#ifdef DEBUG
		debug_print_fct_table_t(fct_ptr);
#endif

		dl_status_t status = _pa_free(fct_ptr->addr);

		if (status != DL_SUCCESS)
		{
			return status;
		}

		fct_ptr->addr = NULL;

		_pa_remove_lru_table(fct_ptr->lru_entry);
		free(fct_ptr->lru_entry);

		fct_ptr->lru_entry = NULL;
		fct_ptr->status &= _pa_fct_not_loaded;
#ifdef DEBUG
		debug_print_fct_table_t(fct_ptr);
#endif
		return DL_SUCCESS;
	}

	return PA_FUNCTION_NOT_LOADED;
}

dl_status_t dl_unload_fct(const char *fct_name)
{
	dl_status_t status;
	write_lock(&table_lock);

	if (_fct_table == NULL)
	{
		status = PA_EMPTY_FUNCTION_TABLE;
		goto END;
	}

	_pa_fct_table_t *fct_table_ptr = _pa_find_sym_by_name(fct_name, _fct_table);

	if (fct_table_ptr != NULL)
	{
		status = _pa_unload_fct_ex(fct_table_ptr);
		goto END;
	}

	status = PA_FUNCTION_NOT_FOUND;
	END:
	write_unlock(&table_lock);
	return status;
}

dl_status_t dl_update_fct(dl_file_handle_t hndl, const char *fct_name, void* file_ptr)
{
	write_lock(&table_lock);
	dl_status_t res = _pa_update_fct_ex(hndl, fct_name, file_ptr);
	write_unlock(&table_lock);
	return res;
}

static dl_status_t _pa_update_fct_ex(dl_file_handle_t hndl, const char *fct_name, void* file_ptr)
{
	dl_status_t status = DL_SUCCESS;
	// We get the id of the function we should update and the ptr to the new elf containing the new function

	// First, get the symbol of the old function.
	_pa_fct_table_t *fct = _pa_find_sym_by_name(fct_name, _fct_table);

	if (fct == NULL)
	{
		return PA_FUNCTION_NOT_FOUND;
	}

	if (unlikely(_PA_FCT_IS_LOADING(fct->status)))
	{
		// function is currently loading so we can't do our stuff, this should not happen
		return PA_FUNCTION_LOADING;
	}

	if (fct->calls_in_progress != 0)
	{
		// function is currently executing.
		return PA_FUNCTION_BLOCKED;
	}

	// unload function if loaded
	if (_PA_FCT_IS_LOADED(fct->status))
	{
		dl_status_t ret = _pa_unload_fct_ex(fct);
		if (ret != DL_SUCCESS && ret != PA_FUNCTION_NOT_LOADED)
		{
			return ret;
		}
	}

	// Build new function thingy
	_pa_fct_table_t new_fct;
	new_fct.id = fct->id;
	new_fct.resolved_relocations = NULL;
	new_fct.relocation_entries = 0;
	new_fct.parent_relocations = NULL;
	new_fct.indirect_dependencies = NULL;
	new_fct.addr = NULL;
	new_fct.pred = fct->pred;
	new_fct.succ = fct->succ;
	new_fct.status = _pa_fct_zero_state;
	new_fct.calls_in_progress = 0;
	new_fct.lru_entry = fct->lru_entry;
	new_fct.version = (uint16_t) (fct->version + 1);

	// Create new file_table for the relocation function to look into
	_pa_file_table_t new_ft;
	new_ft.pred = NULL;
	new_ft.succ = NULL;
	new_ft._fct_table = NULL;
	new_ft._local_obj_table = NULL;
	new_ft.symbol_table = NULL;
	new_ft.symbol_table_entries = 0;
	new_ft.string_table = NULL;
	new_ft.id = hndl;
	new_ft.section_header_string_table = NULL;
	new_fct.file_table_entry = &new_ft;

	memcpy(new_fct.fct_name, fct->fct_name, strlen((const char *)fct->fct_name) + 1);

	elf_header_t *elf_header = (elf_header_t *)file_ptr;
	elf_section_header_t *section_headers = file_ptr + elf_header->section_header_offset;
	unsigned char *section_header_string_table = file_ptr + section_headers[elf_header->section_header_string_table_index].offset;

	for (int i = 0; i < elf_header->sectionHeaderCount; i++)
	{
		if (section_headers[i].type == section_type_symtab)
		{
			// Copy symbol table into enclave
			uint64_t symbol_table_size = section_headers[i].size;
			new_ft.symbol_table = malloc(symbol_table_size);
			if (new_ft.symbol_table == NULL)
			{
				abort();
			}
			memcpy(new_ft.symbol_table, file_ptr + section_headers[i].offset, symbol_table_size);
			new_ft.symbol_table_entries = symbol_table_size / section_headers[i].entsize;

			// TODO: make this one malloc...

			// Copy symbol and section header string table into enclave
			elf_section_header_t *string_table = section_headers + section_headers[i].link;
			uint64_t string_table_size = string_table->size;
			uint64_t section_header_string_table_size = section_headers[elf_header->section_header_string_table_index].size;
			new_ft.string_table = malloc(string_table_size + section_header_string_table_size);
			if (new_ft.string_table == NULL)
			{
				abort();
			}
			new_ft.section_header_string_table = new_ft.string_table + string_table_size;
			memcpy(new_ft.string_table, file_ptr + string_table->offset, string_table_size);
			memcpy(new_ft.section_header_string_table, section_header_string_table, section_header_string_table_size);
			break;
		}
	}

	// Go over the symbol table to find the correct symbol
	char *rela_section_name, *text_section_name;

	if ((rela_section_name = malloc(strlen(PREFIX_RELA) + strlen(PREFIX_TEXT) + strlen((const char *)new_fct.fct_name) + 1)) == NULL)
	{
		abort();
	}

	text_section_name = rela_section_name + strlen(PREFIX_RELA);
	memcpy(rela_section_name, PREFIX_RELA, strlen(PREFIX_RELA));
	memcpy(text_section_name, PREFIX_TEXT, strlen(PREFIX_TEXT));
	memcpy(text_section_name + strlen(PREFIX_TEXT), new_fct.fct_name, strlen((const char *)new_fct.fct_name) + 1);

	int64_t text_section_index = -1, rela_section_index = -1;

	for (unsigned int i = 0; i < elf_header->sectionHeaderCount; i++)
	{
#ifdef DEBUG_PA_ADD_FCT_EX_SECTION_HEADER
		debug_print_elf_section_header(&new_file_entry->section_header[i],section_string_table,i);
#endif
		if (!strcmp(text_section_name, (const char*)&section_header_string_table[section_headers[i].name_offset]))
		{
			text_section_index = i;
		}
		else if (!strcmp(rela_section_name, (const char *)&section_header_string_table[section_headers[i].name_offset]))
		{
			rela_section_index = i;
		}
	}

	free(rela_section_name);

	if (text_section_index == -1)
	{
		return PA_FUNCTION_NOT_FOUND;
	}

	// Copy relocation table
	if (rela_section_index != -1)
	{
		if ((status = _pa_copy_relocations(&new_fct, elf_header, rela_section_index)) != DL_SUCCESS)
		{
			return status;
		}
	}

	// Copy opcode
	elf_section_header_t *text_section_header = section_headers + text_section_index;
	void *opcode = file_ptr + text_section_header->offset;
	sgx_status_t ret = sgx_sha256_msg(opcode, text_section_header->size, &new_fct.opcode_hash);
	if (ret != SGX_SUCCESS)
	{
		return DL_HASH_FAILED;
	}
	new_fct.sealed_size = sgx_calc_sealed_data_size(0, text_section_header->size);
	new_fct.opcode_size = text_section_header->size;
	sgx_sealed_data_t *sealed_data = malloc(new_fct.sealed_size);
	uint8_t _copy_to_enclave = 0;
	if (sgx_is_outside_enclave(opcode, new_fct.opcode_size))
	{
		// move opcode inside enclave for sealing
		opcode = malloc(new_fct.opcode_size);
		if (opcode == NULL)
		{
			return PA_MALLOC_FAILED;
		}
		_copy_to_enclave = 1;
		memcpy(opcode, file_ptr + text_section_header->offset, new_fct.opcode_size);
	}

	if (sealed_data == NULL)
	{
		return PA_MALLOC_FAILED;
	}
	ret = sgx_seal_data(0, NULL, new_fct.opcode_size, opcode, new_fct.sealed_size, sealed_data);
	if (ret != SGX_SUCCESS)
	{
		free(sealed_data);
		return DL_SEAL_FAILED;
	}

	ret = ocall_malloc(&new_fct.sealed_opcode, new_fct.sealed_size);
	if (ret != SGX_SUCCESS)
	{
		free(sealed_data);
		return PA_MALLOC_FAILED;
	}

	memcpy(new_fct.sealed_opcode, sealed_data, new_fct.sealed_size);
	free(sealed_data);
	if (_copy_to_enclave == 1)
	{
		free(opcode);
	}
	////////

	// The parents will stay the same but the indirect deps might not.
	// Also, the parents of other functions that reference this function might be wrong now so we have to fix this up.
	// First, delete all this.
	_pa_del_fct_obj(fct);

	// Set new opcode storage location and relocations
	fct->sealed_opcode = new_fct.sealed_opcode;
	fct->opcode_size = new_fct.opcode_size;
	fct->sealed_size = new_fct.sealed_size;
	memcpy(fct->opcode_hash, new_fct.opcode_hash, sizeof(sgx_sha256_hash_t));
	fct->resolved_relocations = new_fct.resolved_relocations;
	fct->relocation_entries = new_fct.relocation_entries;
	fct->parent_relocations = NULL;
	fct->indirect_dependencies = NULL;
	fct->version += 1;

	// pa_copy_relocations might have added additional local objects
	_pa_obj_table_t *lobj = new_ft._local_obj_table;
	while (lobj != NULL)
	{
		//debug_printf("Potential new object\"%s\"\n", lobj->name);
		_pa_obj_table_t *old = _pa_find_obj_by_name(lobj->name, fct->version, fct->file_table_entry->_local_obj_table);
		// Multiple cases exist:
		// We do not know an object with this name -> Add it with version 0
		// We know an object with this name, but a lower version -> Add it anew, with a higher version
		// We know an object with this name, but the same version -> abort, should not happen?
		// Well, it can happen if two different patches try to add the same object but this should be caught by the developer
		if (old != NULL && old->version == fct->version)
		{
			// We already know this local object but pa_copy_relocations recreated it which is weird!
			abort();
		}
		// old is the wrong name here as it is after this call a newly added object
		_pa_add_obj(lobj->name, fct->file_table_entry->id, &fct->file_table_entry->_local_obj_table, &old);
		old->addr = lobj->addr;
		old->size = lobj->size;
		old->alignment_offset = lobj->alignment_offset;
		old->alignment = lobj->alignment;
		old->version = fct->version; // Do not use lobj->version as it is wrong
		object_counter++;

		// free the temporary object and go to the next one
		_pa_obj_table_t *prev = lobj;
		lobj = lobj->succ;
		free(prev);
	}

	free(new_ft.symbol_table);
	free(new_ft.string_table);

	// Resolve relocations
	while (_pa_resolve_all_relocations() != 0);

	//status = _pa_load_fct_ex(fct);

	return status;
}

/**
 * @brief This function is doing the actual relocation (linking)
 * @param rel_type The relocation type
 * @param addend ?
 * @param destination_ptr A pointer to the memory where the relocation should happen (i.e., a pointer to the memory after the jump/call instruction)
 * @param data_ptr The target of the relocation ?
 * @return
 */
dl_status_t _pa_relocation(Elf_Word rel_type, Elf_SDword addend, void *destination_ptr, void **data_ptr, uint64_t alignment_offset)
{
	if (destination_ptr == NULL || destination_ptr < 0x1000 || data_ptr == NULL || *data_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	if (rel_type == R_X86_64_PLT32 || rel_type == R_X86_64_PC32)
	{
		data_ptr = *data_ptr + addend + 4;
		data_ptr = (void*)data_ptr + alignment_offset;
	}
	else if (rel_type == R_X86_64_REX_GOTP || rel_type == R_X86_64_GOTPCREL)
	{
		//If this relocation type got an addend, we have to create an address table.
	}
	else if (rel_type == R_X86_64_64)
	{
		data_ptr = *data_ptr + addend;
		data_ptr = (void*)data_ptr + alignment_offset;

		for (int i = 0; i < 8; i++)
		{
			*((char *) destination_ptr + i) = ((char *)&data_ptr)[i];
		}

		return DL_SUCCESS;
	}
	else
	{
		return PA_UNSUPPORTED_RELOCATION_TYPE;
	}


	void *next_instruction = destination_ptr + 4;
	unsigned long int offset;

#ifdef DEBUG
	debug_print_pointer(next_instruction);
	debug_print_pointer(data_ptr);
#endif

	if ((unsigned long int) next_instruction < (unsigned long int) data_ptr)
	{
		offset = (void *) data_ptr - next_instruction;
	}
	else if ((unsigned long int) next_instruction > (unsigned long int) data_ptr)
	{
		offset = next_instruction - (void *) data_ptr;
		offset = ~offset;
		offset++;
	}

#ifdef DEBUG
	debug_print_int(&offset);
	debug_print_int(destination_ptr);
#endif

	///////////////////////////////////////////////////////////////
	if ((unsigned int) offset == *(unsigned int *) destination_ptr)
	{
		return DL_SUCCESS;
	}
	///////////////////////////////////////////////////////////////

	for (int i = 0; i < 4; i++)
	{
		*((char *) destination_ptr + i) = ((char *) &offset)[i];
	}

#ifdef DEBUG
	debug_print_int(destination_ptr);
#endif

	return DL_SUCCESS;
}

static dl_status_t _pa_update_lru_table(_pa_fct_lru_table_t *entry_ptr)
{
	if (entry_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	write_lock(&lru_lock);

	if (entry_ptr->pred == NULL && entry_ptr->succ == NULL)
	{
		if (_lru_first == NULL && _lru_last == NULL)
		{
			_lru_first = entry_ptr;
			_lru_last = entry_ptr;
			goto END;
		}

		if (_lru_first == entry_ptr && _lru_last == entry_ptr)
		{
			goto END;
		}

		_lru_last->succ = entry_ptr;
		entry_ptr->pred = _lru_last;
		_lru_last = entry_ptr;
		goto END;
	}

	if (entry_ptr->pred != NULL && entry_ptr->succ == NULL)
	{
		goto END;
	}

	if (entry_ptr->pred == NULL && entry_ptr->succ != NULL)
	{
		entry_ptr->succ->pred = NULL;
		_lru_first = entry_ptr->succ;
	}
	else
	{
		entry_ptr->pred->succ = entry_ptr->succ;
		entry_ptr->succ->pred = entry_ptr->pred;
	}

	entry_ptr->succ = NULL;
	entry_ptr->pred = _lru_last;
	_lru_last->succ = entry_ptr;
	_lru_last = entry_ptr;

	END:
	write_unlock(&lru_lock);
	return DL_SUCCESS;
}

static dl_status_t _pa_remove_lru_table(_pa_fct_lru_table_t *entry_ptr)
{
	if (entry_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	write_lock(&lru_lock);

	if (entry_ptr->pred == NULL && entry_ptr->succ == NULL)
	{
		_lru_first = NULL;
		_lru_last = NULL;
		goto END;
	}
	else if (entry_ptr->pred != NULL && entry_ptr->succ == NULL)
	{
		entry_ptr->pred->succ = NULL;
		_lru_last = entry_ptr->pred;
		goto END;
	}
	else if (entry_ptr->pred == NULL && entry_ptr->succ != NULL)
	{
		entry_ptr->succ->pred = NULL;
		_lru_first = entry_ptr->succ;
		goto END;
	}
	else
	{
		entry_ptr->pred->succ = entry_ptr->succ;
		entry_ptr->succ->pred = entry_ptr->pred;
		goto END;
	}

	END:
	write_unlock(&lru_lock);
	return DL_SUCCESS;
}

void __attribute__((weak)) pa_print_error(const char *fmt, ...)
{
	(void)fmt;
	// do nothing;
}

static dl_status_t _pa_check_fct_consistency(_pa_fct_table_t *fct)
{
	if (fct->addr == NULL)
	{
		// Check if unloaded functions have correct status (not loaded or loading)
		if (_PA_FCT_IS_LOADED(fct->status) || _PA_FCT_IS_LOADING(fct->status))
		{
			pa_print_error("Function has LOADED or LOADING flag but has no address!\nName: %s\nID: %lu\n", fct->fct_name, fct->id);
			return PA_CONSISTENCY_ERROR;
		}
	}
	else
	{
		// Check if loaded functions have correct status (loaded and not loading)
		if (!_PA_FCT_IS_LOADED(fct->status) || _PA_FCT_IS_LOADING(fct->status))
		{
			pa_print_error("Function does not have LOADED flag or does have LOADING flag but has an address!\nName: %s\nID: %lu\n", fct->fct_name, fct->id);
			return PA_CONSISTENCY_ERROR;
		}
	}

	if (fct->calls_in_progress != 0)
	{
		pa_print_error("Function has non-zero (%u) calls in progress!\nName: %s\nID: %lu\n", fct->calls_in_progress, fct->fct_name, fct->id);
		return PA_CONSISTENCY_ERROR;
	}

	// Check if this function is referenced as a parent in its function relocations
	for (uint64_t i = 0; i < fct->relocation_entries; ++i)
	{
		_pa_relocation_t *rel = &fct->resolved_relocations[i];

		if (rel->resolved != 1 || ELF_S_TYPE(rel->symbol.info) != symbol_type_fct)
		{
			continue;
		}

		bool found = false;
		_pa_parent_relocation_t *pit1 = rel->ref.fct->parent_relocations;
		while (pit1 != NULL)
		{
			if (pit1->parent == fct)
			{
				found = true;
				break;
			}
			pit1 = pit1->next;
		}
		if (!found)
		{
			pa_print_error("Function \"%s\" is not referenced in its relocation \"%s\" as a parent!\n", fct->fct_name, rel->ref.fct->fct_name);
			return PA_CONSISTENCY_ERROR;
		}
	}

	// Check if this function is referenced as a dependency in its parents and parent's parents, etc...
	_pa_parent_relocation_t *pit = fct->parent_relocations;
	while (pit != NULL)
	{
		// Go through the deps of this parent
		_pa_indirect_dependency_t *dit = pit->parent->indirect_dependencies;
		bool found = false;
		while (dit != NULL)
		{
			if (dit->fct == fct)
			{
				found = true;
				break;
			}
			dit = dit->next;
		}
		if (!found)
		{
			pa_print_error("Function \"%s\" is not referenced in its parent \"%s\" as a dependency!\n", fct->fct_name, pit->parent->fct_name);
			return PA_CONSISTENCY_ERROR;
		}
		pit = pit->next;
	}

	return DL_SUCCESS;
}

dl_status_t dl_check_consistency()
{
	write_lock(&table_lock);
	_pa_fct_table_t *fit = _fct_table;
	_pa_fct_table_t *prev = NULL;
	dl_status_t status;

	while (fit != NULL)
	{
		// Check double-linked list consistency
		if (fit->pred != prev)
		{
			pa_print_error("Linked-list inconsistency!\n");
			write_unlock(&table_lock);
			return PA_CONSISTENCY_ERROR;
		}

		if ((status = _pa_check_fct_consistency(fit)) != DL_SUCCESS)
		{
			write_unlock(&table_lock);
			return status;
		}

		prev = fit;
		fit = fit->succ;
	}

	_pa_file_table_t *file = _file_table;
	_pa_file_table_t *fprev = NULL;
	while (file != NULL)
	{
		if (file->pred != fprev)
		{
			pa_print_error("Linked-list inconsistency!\n");
			write_unlock(&table_lock);
			return PA_CONSISTENCY_ERROR;
		}

		fit = file->_fct_table;
		prev = NULL;
		while (fit != NULL)
		{
			// Check double-linked list consistency
			if (fit->pred != prev)
			{
				pa_print_error("Linked-list inconsistency!\n");
				write_unlock(&table_lock);
				return PA_CONSISTENCY_ERROR;
			}

			if ((status = _pa_check_fct_consistency(fit)) != DL_SUCCESS)
			{
				write_unlock(&table_lock);
				return status;
			}

			prev = fit;
			fit = fit->succ;
		}

		fprev = file;
		file = file->succ;
	}

	write_unlock(&table_lock);
	return DL_SUCCESS;
}

char *dl_get_error()
{
	return _dl_error_msg;
}

int fct_comparer(const void *left, const void *right)
{
	_pa_fct_table_t *fa = *((_pa_fct_table_t **)left);
	_pa_fct_table_t *fb = *((_pa_fct_table_t **)right);

	int val = memcmp(fa->opcode_hash, fb->opcode_hash, sizeof(sgx_sha256_hash_t));

	if (val == 0)
	{
		// if code is the same sort by symbol name
		val = strncmp((char *)fa->fct_name, (char *)fb->fct_name, PA_MAX_FCT_NAME_LENGTH);
	}

	return val;
}

int obj_comparer(const void *left, const void *right)
{
	_pa_obj_table_t *oa = *((_pa_obj_table_t **)left);
	_pa_obj_table_t *ob = *((_pa_obj_table_t **)right);

	int val = strncmp(oa->name, ob->name, PA_MAX_OBJ_NAME_LENGTH);
	if (val == 0)
	{
		// if name is identical, compare size
		val = (int)((int)oa->size - (int)ob->size);
	}
	if (val == 0)
	{
		// if name and size are identical, compare version
		val = (int)((int)oa->version - (int)ob->version);
	}

	return val;
}

static bool _dl_is_fct_unused(_pa_fct_table_t *fct)
{
	// edge functions are always used
	if (fct->edge_fct)
	{
		return false;
	}
	// non-edge functions start here
	// if it has no parents, it's not used
	if (fct->parent_relocations == NULL)
	{
		return true;
	}
	// if it has parents, find out if ALL parents are unused
	_pa_parent_relocation_t *prit = fct->parent_relocations;
	while (prit != NULL)
	{
		if (!_dl_is_fct_unused(prit->parent))
		{
			return false;
		}
		prit = prit->next;
	}
	return true;
}

dl_status_t dl_measure(dl_measurement_t *msr)
{
	sgx_sha_state_handle_t hndl;
	sgx_sha256_init(&hndl);

	read_lock(&table_lock);

	// First, create an array that contains all fcts
	_pa_fct_table_t **fcts = calloc(function_counter, sizeof(_pa_fct_table_t *));
	_pa_obj_table_t **objs = calloc(object_counter, sizeof(_pa_obj_table_t *));
	uint32_t num_fcts = 0, num_objs = 0;

	_pa_file_table_t *fit = _file_table;
	while (fit != NULL)
	{
		_pa_fct_table_t *fcit = fit->_fct_table;
		while (fcit != NULL)
		{
			fcts[num_fcts++] = fcit;
			fcit = fcit->succ;
		}
		_pa_obj_table_t *objit = fit->_local_obj_table;
		while (objit != NULL)
		{
			objs[num_objs++] = objit;
			objit = objit->succ;
		}
		fit = fit->succ;
	}
	_pa_fct_table_t *fcit = _fct_table;
	while (fcit != NULL)
	{
		fcts[num_fcts++] = fcit;
		fcit = fcit->succ;
	}
	_pa_obj_table_t *objit = _obj_table;
	while (objit != NULL)
	{
		objs[num_objs++] = objit;
		objit = objit->succ;
	}

	// Sort the array
	qsort(fcts, num_fcts, sizeof(_pa_fct_table_t *), fct_comparer);

	// Hash all metadata and gather the referenced objects from the functions
	for (uint32_t j = 0; j < num_fcts; ++j)
	{
		_pa_fct_table_t *f = fcts[j];
		// An unused function will have no parents or all parents are themselves unused.
		// Also, it must be a local function as global functions might have no parents or they are the external interface so they are implictly used.
		// Everything used by a used function is also used.

		sgx_sha256_update(f->fct_name, strnlen((char *)f->fct_name, PA_MAX_FCT_NAME_LENGTH), hndl);
		sgx_sha256_update(f->opcode_hash, sizeof(sgx_sha256_hash_t), hndl);
	}

	free(fcts);

	// Now handle objects

	// Sort the array
	qsort(objs, num_objs, sizeof(_pa_obj_table_t *), obj_comparer);

	// Hash all metadata
	for (uint32_t j = 0; j < num_objs; ++j)
	{
		// TODO: for .rodata object also include hash as content should never change
		//debug_printf("obj \"%s\" v%u\n", objs[j]->name, objs[j]->version);
		sgx_sha256_update((char *)objs[j]->name, strnlen(objs[j]->name, PA_MAX_OBJ_NAME_LENGTH), hndl);
		//sgx_sha256_update((uint8_t*)&objs[j]->size, sizeof(objs[j]->size), hndl);
		//sgx_sha256_update((uint8_t*)&objs[j]->version, sizeof(objs[j]->version), hndl);
	}

	free(objs);

	sgx_sha256_get_hash(hndl, &msr->hash);

	sgx_sha256_close(hndl);

	read_unlock(&table_lock);

	return DL_SUCCESS;
}

typedef struct
{
	union {
		_pa_fct_table_t **ftbl;
		_pa_obj_table_t **otbl;
	} tbl;
	union {
		_pa_fct_table_t *fct;
		_pa_obj_table_t *obj;
	} ent;
} _dl_entry_t;
static uint32_t _dl_cleanup()
{
	uint32_t changes = 0;
	// First, create an array that contains all fcts
	//uint32_t num_fcts = 0;
	_dl_entry_t *fcts = calloc(function_counter, sizeof(_dl_entry_t));
	_dl_entry_t *objs = calloc(object_counter, sizeof(_dl_entry_t));
	uint32_t num_fctsi = 0, num_objs = 0;

	_pa_file_table_t *fit = _file_table;
	while (fit != NULL)
	{
		_pa_fct_table_t *fcit = fit->_fct_table;
		while (fcit != NULL)
		{
			if (_dl_is_fct_unused(fcit))
			{
				_pa_fct_table_t *temp = fcit;
				fcit = fcit->succ;
				debug_printf("[cleanup] unused local fct \"%s\"\n", temp->fct_name);
				_dl_del_fct((char *)temp->fct_name, &fit->_fct_table);
				function_counter--;
				changes++;
			}
			else
			{
				fcts[num_fctsi].tbl.ftbl = &fit->_fct_table;
				fcts[num_fctsi++].ent.fct = fcit;
				fcit = fcit->succ;
			}
		}
		_pa_obj_table_t *objit = fit->_local_obj_table;
		while(objit != NULL)
		{
			objs[num_objs].tbl.otbl = &fit->_local_obj_table;
			objs[num_objs++].ent.obj = objit;
			objit = objit->succ;
		}
		fit = fit->succ;
	}
	_pa_fct_table_t *fcit = _fct_table;
	while (fcit != NULL)
	{
		if (_dl_is_fct_unused(fcit))
		{
			_pa_fct_table_t *temp = fcit;
			fcit = fcit->succ;
			debug_printf("[cleanup] unused global fct \"%s\"\n", temp->fct_name);
			_dl_del_fct((char *)temp->fct_name, &_fct_table);
			function_counter--;
			changes++;
		}
		else
		{
			fcts[num_fctsi].tbl.ftbl = &_fct_table;
			fcts[num_fctsi++].ent.fct = fcit;
		}
		fcit = fcit->succ;
	}
	_pa_obj_table_t *objit = _obj_table;
	while(objit != NULL)
	{
		objs[num_objs].tbl.otbl = &_obj_table;
		objs[num_objs++].ent.obj = objit;
		objit = objit->succ;
	}

	// Iterate over the functions and remove all objs that are in use
	for (uint32_t k = 0; k < num_fctsi; ++k)
	{
		for (uint32_t r = 0; r < fcts[k].ent.fct->relocation_entries; ++r)
		{
			_pa_relocation_t *rel = &fcts[k].ent.fct->resolved_relocations[r];
			if (!rel->resolved)
			{
				continue;
			}
			if (ELF_S_TYPE(rel->symbol.info) != symbol_type_obj)
			{
				continue;
			}
			for (uint32_t s = 0; s < num_objs; ++s)
			{
				if (objs[s].ent.obj == rel->ref.obj)
				{
					objs[s].ent.obj = NULL;
					break;
				}
			}
		}
	}

	// This now leaves an array which only contains unused objs
	for (uint32_t s = 0; s < num_objs; ++s)
	{
		if (objs[s].ent.obj != NULL)
		{
			debug_printf("[cleanup] unused obj: \"%s\"\n", objs[s].ent.obj->name);
			_pa_obj_table_t *o = objs[s].ent.obj;
			void *t = o->addr;
			o->addr = NULL;
			_pa_free(t);
			if (o->succ != NULL)
			{
				o->succ->pred = o->pred;
			}
			if (o->pred != NULL)
			{
				o->pred->succ = o->succ;
			}
			else
			{
				// TODO: set table pointer to o->succ
				*objs[s].tbl.otbl = o->succ;
			}
			free(o);
			changes++;

			object_counter--;
			break;
		}
	}

	free(fcts);
	free(objs);

	return changes;
}

dl_status_t dl_patch(void *file_ptr, dl_patch_desc_t *desc)
{
	// TODO make patch desc discoverable from file_ptr
	// 1. add stuff
	// 2. (pre-update state transfer fcts)
	// 3. update fcts
	// 4. (post-update state transfer fcts)
	// 5. remove explicitly named symbols
	// 6. cleanup (remove all unused symbols)

	// IDEA: state transfer functions possible: int __name__(void * old, void * new)
	// old is address of old object, new address of new object
	// 1. allocate new object
	// 2. call __name__
	// 3. swap addr ptr in object to new
	// 4. free old
	// Remove version numbers then from objects and functions as now only one version of the object can exist.

	// First, we need to find the patch description struct

	if (file_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	write_lock(&table_lock);

	dl_status_t status = DL_SUCCESS;
	dl_file_handle_t hndl = DL_EMPTY_HANDLE;
	status = _dl_add_file(file_ptr, &hndl);
	if (status != DL_SUCCESS)
	{
		goto END;
	}

	if (desc->add_symbols != NULL)
	{
		char *token = strtok(desc->add_symbols, " ");

		while (token != NULL)
		{
			_pa_fct_table_t *fct = NULL;
			debug_printf("[patch] adding fct \"%s\"\n", token);
			status = _pa_add_fct_ex(hndl, token, &_fct_table, &fct);
			if (status == DL_SUCCESS)
			{
				function_counter++;
				fct->edge_fct = true;
			}
			else
			{
				goto END;
			}
			token = strtok(NULL, " ");
		}
	}

	// TODO: before doing state transfer functions, move the lock out of _pa_call_ex into dl_call and dl_call_ex
	// TODO: this might be complicated, as there is an lock_upgrade inside _pa_call_ex

	if (desc->update_symbols != NULL)
	{
		char *token = strtok(desc->update_symbols, " ");

		while (token != NULL)
		{
			debug_printf("[patch] updating fct \"%s\"\n", token);
			status = _pa_update_fct_ex(hndl, token, file_ptr);
			if (status != DL_SUCCESS)
			{
				goto END;
			}
			token = strtok(NULL, " ");
		}
	}

	// TODO: before doing state transfer functions, move the lock out of _pa_call_ex into dl_call and dl_call_ex
	// TODO: this might be complicated, as there is an lock_upgrade inside _pa_call_ex

	if (desc->remove_symbols != NULL)
	{
		char *token = strtok(desc->remove_symbols, " ");

		while (token != NULL)
		{
			debug_printf("[patch] removing fct \"%s\"\n", token);
			status = _dl_del_fct(token, &_fct_table);
			if (status != DL_SUCCESS && status != PA_FUNCTION_NOT_FOUND)
			{
				goto END;
			}
			status = DL_SUCCESS;
			token = strtok(NULL, " ");
		}
	}

	while (_pa_resolve_all_relocations() != 0);

	// Now clean up all unused functions and objects
	while (_dl_cleanup() != 0);

	END:
	write_unlock(&table_lock);

	return status;
}
