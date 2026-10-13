cmake_minimum_required(VERSION 3.22)
project(Driver)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add custom module path if needed
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/")
find_package(CrossWDK REQUIRED)

# Get current UNIX time at CMake configure time
string(TIMESTAMP CURRENT_UNIX_TIME "%s" UTC)
add_compile_definitions(SEED=${CURRENT_UNIX_TIME})

# Generate seed.h with SEED macro (NOT ADDING THIS DOES NOT WORK)
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/seed.h" "#pragma once\n#define SEED ${CURRENT_UNIX_TIME}\n")

# Driver entry point
wdk_add_driver(Driver
        main.cpp
)

# Per-target compile and link options
target_compile_options(Driver PRIVATE
        -Oz                       # Optimize for size aggressively
        -flto                     # Enable Link-Time Optimization
        -ffunction-sections       # Place each function in its own section
        -fdata-sections           # Place each data item in its own section
        -fno-exceptions           # Disable exception handling (not supported in kernel)
        -fno-rtti                 # Disable RTTI (not needed)
        -fno-unwind-tables        # Don't generate unwind tables
        -fno-asynchronous-unwind-tables  # Avoid async unwind info (reduces size)
        -g0                       # No debug info
        -nostdlib                 # Don't use standard libraries
)

target_link_options(Driver PRIVATE
        -Wl,--gc-sections         # Remove unused sections
        -Wl,--strip-all           # Strip all symbol info
        -flto                     # LTO for cross-module optimization
)

# Code signing (optional): finds signtool in any installed Windows Kit, and takes the PFX password from the
# environment instead of storing it in this file. Signing is skipped (with a warning) when either is missing.
find_program(SIGNTOOL signtool
        PATHS "C:/Program Files (x86)/Windows Kits/10/bin/x86"
              "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x86"
        NO_DEFAULT_PATH)
if(SIGNTOOL AND DEFINED ENV{TESTSIGN_PFX_PASSWORD})
        add_custom_command(TARGET Driver POST_BUILD
                COMMAND "${SIGNTOOL}" sign /v
                /f "${CMAKE_CURRENT_SOURCE_DIR}/TestSign.pfx"
                /p "$ENV{TESTSIGN_PFX_PASSWORD}"
                /t http://timestamp.digicert.com
                /fd sha256
                "${CMAKE_BINARY_DIR}/Driver.sys"
        )
else()
        message(WARNING "Driver.sys will not be signed: needs signtool and the TESTSIGN_PFX_PASSWORD environment variable")
endif()