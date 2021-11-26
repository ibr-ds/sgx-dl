project(sgx-dl)
cmake_minimum_required(VERSION 3.4)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


# Driver targets for building and loading

add_custom_target(driver
        COMMAND make
        BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx-driver/isgx.ko
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx-driver
        )

# Loads the custom driver and restarts aesmd
add_custom_target(load_driver
        COMMAND ../scripts/load.bash
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx-driver
        )

add_dependencies(load_driver driver)

# Unloads the custom driver and restores the reference driver
add_custom_target(unload_driver
        COMMAND ../scripts/load.bash
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx-driver
        )

add_dependencies(unload_driver driver)


# SDK/PSW targets for building and installing

add_custom_target(sdk
        COMMAND make
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx
        )

add_custom_target(sdk_bin
        COMMAND make sdk_install_pkg
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx
        )
add_dependencies(sdk_bin sdk)

add_custom_target(sdk_install
        COMMAND ../scripts/install_sdk.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx
        )
add_dependencies(sdk_install sdk_bin)

add_custom_target(psw_bin
        COMMAND export DEB_BUILD_OPTIONS="nostrip"
        COMMAND make deb_sgx_enclave_common_pkg
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx
        )
add_dependencies(psw_bin sdk)

add_custom_target(psw_install
        COMMAND ../scripts/install_psw.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/linux-sgx
        )
add_dependencies(psw_install psw_bin)

add_custom_target(dev_install)
add_dependencies(dev_install psw_install sdk_install)


add_subdirectory(libpa)
add_subdirectory(example)
