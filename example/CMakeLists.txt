find_package(SGXSDK REQUIRED)

set(LDS_NAME enclave.lds)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/enclave_u.c ${CMAKE_CURRENT_SOURCE_DIR}/src/enclave_u.h ${CMAKE_CURRENT_SOURCE_DIR}/src/enclave_t.c ${CMAKE_CURRENT_SOURCE_DIR}/src/enclave_t.h
        COMMAND ${SGXSDK_EDGER8R} --search-path misc --search-path ../libpa/misc --search-path ${SGXSDK_INCLUDE_DIRS} --untrusted-dir src --trusted-dir src enclave.edl
        DEPENDS misc/enclave.edl
        DEPENDS ../libpa/misc/dl_library.edl
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/misc/enclave.pem
        COMMAND openssl genrsa -out misc/enclave.pem -3 3072
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(generate_key_example DEPENDS misc/enclave.pem)

set(EXAMPLE_APP_SOURCE_FILES
        src/app.cpp
        src/enclave_u.c)

set(EXAMPLE_ENC_SOURCE_FILES
        src/enclave.cpp
        src/enclave_t.c)

set(EXAMPLE_BASELINE1_ENC_SOURCE_FILES
        src/enclave.cpp
        src/loadable.c
        src/add.c
        src/enclave_t.c)

set(EXAMPLE_BASELINE2_ENC_SOURCE_FILES
        src/enclave.cpp
        src/loadable.c
        src/patch.c
        src/enclave_t.c)

set(EXAMPLE_LOADABLE_SOURCE_FILES
        src/loadable.c
        src/lib.o
        src/add.c
        src/patch.c)

set(ENCL_FLAGS "-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGXSDK_ENCL_LIB_DIR} -Wl,--whole-archive \
        -l${SGXSDK_TRTS} -Wl,--no-whole-archive -Wl,--start-group -l${SGXSDK_TSTDC} -l${SGXSDK_TSTDCXX} -l${SGXSDK_TCRYPTO} \
        -l${SGXSDK_TSERVICE} -Wl,--end-group -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry \
        -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/misc/${LDS_NAME}")

add_library(exampleenclave SHARED ${EXAMPLE_ENC_SOURCE_FILES})
target_include_directories(exampleenclave PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} ../libpa/include)
target_compile_options(exampleenclave PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g -O2 -march=native)
target_link_libraries(exampleenclave PUBLIC tpa ${ENCL_FLAGS})
add_dependencies(exampleenclave generate_key_example loadable)

add_library(exampleenclavebench SHARED ${EXAMPLE_ENC_SOURCE_FILES})
target_include_directories(exampleenclavebench PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} ../libpa/include)
target_compile_options(exampleenclavebench PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g -O2 -march=native)
target_compile_definitions(exampleenclavebench PUBLIC BENCHMARK)
target_link_libraries(exampleenclavebench PUBLIC tpa ${ENCL_FLAGS})
add_dependencies(exampleenclavebench generate_key_example loadablebench)

add_library(exampleenclavebenchibaslr SHARED ${EXAMPLE_ENC_SOURCE_FILES})
target_include_directories(exampleenclavebenchibaslr PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} ../libpa/include)
target_compile_options(exampleenclavebenchibaslr PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g -O2 -march=native)
target_compile_definitions(exampleenclavebenchibaslr PUBLIC BENCHMARK)
target_link_libraries(exampleenclavebenchibaslr PUBLIC tpa_ibaslr ${ENCL_FLAGS})
add_dependencies(exampleenclavebenchibaslr generate_key_example loadablebench)

add_custom_command(TARGET exampleenclave POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclave.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclave.signed.so -config misc/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclave.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclave.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclave.signed.so
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(TARGET exampleenclavebench POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebench.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebench.signed.so -config misc/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclavebench.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebench.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclavebench.signed.so
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(TARGET exampleenclavebenchibaslr POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebenchibaslr.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebenchibaslr.signed.so -config misc/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclavebenchibaslr.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexampleenclavebenchibaslr.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexampleenclavebenchibaslr.signed.so
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(exampleapp ${EXAMPLE_APP_SOURCE_FILES})
target_include_directories(exampleapp PUBLIC ${SGXSDK_INCLUDE_DIRS})
target_link_libraries(exampleapp PUBLIC ${SGXSDK_URTS} ${SGXSDK_UAE} pthread upa)
target_compile_options(exampleapp PUBLIC -g)

add_executable(exampleappbench ${EXAMPLE_APP_SOURCE_FILES})
target_include_directories(exampleappbench PUBLIC ${SGXSDK_INCLUDE_DIRS})
target_link_libraries(exampleappbench PUBLIC ${SGXSDK_URTS} ${SGXSDK_UAE} pthread upa)
target_compile_options(exampleappbench PUBLIC -g)
target_compile_definitions(exampleappbench PUBLIC BENCHMARK)

add_library(loadable STATIC ${EXAMPLE_LOADABLE_SOURCE_FILES})
target_compile_options(loadable PUBLIC -fpic -ffunction-sections -fdata-sections -fstack-protector -nostdinc)
target_include_directories(loadable PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} ../libpa/include)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/lib.o
        COMMAND rustc -Cpanic=abort --emit obj -O lib.rs
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_custom_command(TARGET loadable POST_BUILD
        COMMAND cp ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../example/CMakeFiles/loadable.dir/src/*.o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/src/lib.o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/patch.rs.o
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(loadablebench STATIC ${EXAMPLE_LOADABLE_SOURCE_FILES})
target_compile_options(loadablebench PUBLIC -fpic -ffunction-sections -fdata-sections -fstack-protector -nostdinc)
target_compile_definitions(loadablebench PUBLIC BENCHMARK)
target_include_directories(loadablebench PUBLIC ${SGXSDK_ENCL_C_INCLUDE_DIRS} ../libpa/include)

add_custom_command(TARGET loadablebench POST_BUILD
        COMMAND mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/loadablebench
        COMMAND cp ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../example/CMakeFiles/loadablebench.dir/src/*.o ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/loadablebench
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(examplebaseline1enclave SHARED ${EXAMPLE_BASELINE1_ENC_SOURCE_FILES})
target_include_directories(examplebaseline1enclave PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} ../libpa/include)
target_compile_options(examplebaseline1enclave PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g)
target_compile_definitions(examplebaseline1enclave PUBLIC BASELINE)
target_link_libraries(examplebaseline1enclave PUBLIC tpa ${ENCL_FLAGS})
add_dependencies(examplebaseline1enclave generate_key_example)

add_custom_command(TARGET examplebaseline1enclave POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline1enclave.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline1enclave.signed.so -config misc/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexamplebaseline1enclave.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline1enclave.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexamplebaseline1enclave.signed.so
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_library(examplebaseline2enclave SHARED ${EXAMPLE_BASELINE2_ENC_SOURCE_FILES})
target_include_directories(examplebaseline2enclave PUBLIC ${SGXSDK_ENCL_CXX_INCLUDE_DIRS} ../libpa/include)
target_compile_options(examplebaseline2enclave PUBLIC -nostdinc -nostdinc++ -fvisibility=hidden -fpie -fstack-protector -std=c++11 -g)
target_compile_definitions(examplebaseline2enclave PUBLIC BASELINE)
target_link_libraries(examplebaseline2enclave PUBLIC tpa ${ENCL_FLAGS})
add_dependencies(examplebaseline2enclave generate_key_example)

add_custom_command(TARGET examplebaseline2enclave POST_BUILD
        COMMAND ${SGXSDK_SIGN} sign -key misc/enclave.pem -enclave ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline2enclave.so -out ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline2enclave.signed.so -config misc/enclave.config.xml
        COMMAND rm -f ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexamplebaseline2enclave.signed.so
        COMMAND ln -s ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libexamplebaseline2enclave.signed.so ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/libexamplebaseline2enclave.signed.so
        DEPENDS misc/enclave.config.xml
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
