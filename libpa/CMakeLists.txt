find_package(SGXSDK REQUIRED)

set(PALIB_APP_SOURCE_FILES
        src-u/ocalls.c
        src-u/debug_a.c
        src-u/elf_parser_a.c
        )

set(PALIB_ENC_SOURCE_FILES
        src-t/dynamic_functions_e.c
        src-t/aslr.c
        src-t/elf_parser.c
        src-t/memory_allocator.c
        src-t/rwlock.c)

add_library(tpa STATIC ${PALIB_ENC_SOURCE_FILES})
target_include_directories(tpa PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} ${SGXSDK_EAUG_INCLUDE_DIRS} include src-t)
target_compile_options(tpa PUBLIC -nostdinc -fvisibility=hidden -fpie -fstack-protector -std=c11 -g)
#target_compile_options(tpa PUBLIC -nostdinc -fvisibility=hidden -fpie -fstack-protector -std=c11 -g -O2 -march=native)

add_library(tpa_ibaslr STATIC ${PALIB_ENC_SOURCE_FILES})
target_include_directories(tpa_ibaslr PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} ${SGXSDK_EAUG_INCLUDE_DIRS} include src-t)
target_compile_options(tpa_ibaslr PUBLIC -nostdinc -fvisibility=hidden -fpie -fstack-protector -std=c11 -g)
target_compile_definitions(tpa_ibaslr PUBLIC ASLR_IN_BAND)

add_library(tpa_obaslr STATIC ${PALIB_ENC_SOURCE_FILES})
target_include_directories(tpa_obaslr PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} ${SGXSDK_EAUG_INCLUDE_DIRS} include src-t)
target_compile_options(tpa_obaslr PUBLIC -nostdinc -fvisibility=hidden -fpie -fstack-protector -std=c11 -g)
target_compile_definitions(tpa_obaslr PUBLIC ASLR_OUT_BAND)

add_library(upa STATIC ${PALIB_APP_SOURCE_FILES})
target_include_directories(upa PUBLIC ${SGXSDK_INCLUDE_DIRS} include src-u)
target_compile_options(upa PUBLIC -g -O2 -march=native -fPIC)
target_link_libraries(upa PUBLIC pthread)


## Test application starts here

set(LDS_NAME enclave.lds)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src-test-u/enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/src-test-u/enclave_u.h ${CMAKE_CURRENT_SOURCE_DIR}/src-test-t/enclave_t.c ${CMAKE_CURRENT_SOURCE_DIR}/src-test-t/enclave_t.h
        COMMAND ${SGXSDK_EDGER8R} --search-path misc --search-path misc-test --search-path ${SGXSDK_INCLUDE_DIRS} --untrusted-dir src-test-u --trusted-dir src-test-t enclave.edl
        DEPENDS misc-test/enclave.edl
        DEPENDS misc/dl_library.edl
        DEPENDS misc-test/enclave.config.xml
        DEPENDS include/__debug.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/misc-test/enclave.pem
        COMMAND openssl genrsa -out misc-test/enclave.pem -3 3072
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(generate_key_pa DEPENDS misc-test/enclave.pem)

set(PATEST_APP_SOURCE_FILES
        src-test-u/app.cpp
        src-test-u/enclave_u.c)

set(PATEST_ENC_SOURCE_FILES
        src-test-t/enclave.cpp
        src-test-t/enclave_t.c)

set(PATEST_LOADABLE_SOURCE_FILES
        src-test-t/test.c
        src-test-t/test2.c
        src-test-t/test3.c
        src-test-t/test_cases.c
        src-test-t/test_cases_var.c
        src-test-t/test_cases_abort.c
        src-test-t/test_header_app.c
        src-test-t/test_header_fct.c
        src-test-t/test_datarel.c)


set(ENCL_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGXSDK_ENCL_LIB_DIR} -Wl,--whole-archive \
        -l${SGXSDK_TRTS} -Wl,--no-whole-archive -Wl,--start-group -l${SGXSDK_TSTDC} -l${SGXSDK_TSTDCXX} -l${SGXSDK_TCRYPTO} \
        -l${SGXSDK_TSERVICE} -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry \
        -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/misc-test/${LDS_NAME}")

set(ENCL_SIM_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGXSDK_ENCL_LIB_DIR} -Wl,--whole-archive \
        -l${SGXSDK_TRTS_SIM} -Wl,--no-whole-archive -Wl,--start-group -l${SGXSDK_TSTDC} -l${SGXSDK_TSTDCXX} -l${SGXSDK_TCRYPTO} \
        -l${SGXSDK_TSERVICE_SIM} -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry \
        -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/misc-test/${LDS_NAME}")

add_library(patestenclave SHARED ${PATEST_ENC_SOURCE_FILES})
target_include_directories(patestenclave PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} include include-test src-test-t)
target_compile_options(patestenclave PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g)
target_link_libraries(patestenclave PUBLIC tpa ${ENCL_FLAGS})
add_dependencies(patestenclave generate_key_pa paloadable)
#set_target_properties(enclave PROPERTIES LINK_FLAGS ${ENCL_FLAGS})

add_library(paloadable STATIC ${PATEST_LOADABLE_SOURCE_FILES})
target_compile_options(paloadable PUBLIC -fpic -ffunction-sections -fdata-sections -fstack-protector -nostdinc)
target_include_directories(paloadable PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} include-test)

add_custom_command(TARGET paloadable POST_BUILD
        COMMAND cp ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../libpa/CMakeFiles/paloadable.dir/src-test-t/*.o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(TARGET patestenclave POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc-test/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpatestenclave.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpatestenclave.signed.so -config misc-test/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libpatestenclave.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpatestenclave.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libpatestenclave.signed.so
        DEPENDS misc-test/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(patestapp ${PATEST_APP_SOURCE_FILES})
target_include_directories(patestapp PUBLIC ${SGXSDK_INCLUDE_DIRS} include-test src-test-u)
target_link_libraries(patestapp PUBLIC ${SGXSDK_URTS} ${SGXSDK_UAE} pthread upa)
target_compile_options(patestapp PUBLIC -g)

