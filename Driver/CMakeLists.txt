cmake_minimum_required(VERSION 3.22)
project(Driver)

# Language standard: 23 comes from wdk_add_driver (CXX_STANDARD 23 + REQUIRED). Only the extensions
# switch is set here, so the target does not silently pick up GNU extensions
set(CMAKE_CXX_EXTENSIONS OFF)

# crosswdk supplies the WDK libraries, the kernel build flags (freestanding, no rtti/exceptions, warning
# wall) and the linker entry point via wdk_add_driver below. Anything those already provide is NOT
# repeated here
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/")
find_package(CrossWDK REQUIRED)

# Fixed seed, so the compile-time encoder and the runtime decoder always agree. The previous scheme
# (UNIX time at configure) drifted between the -D flag and the regenerated seed.h whenever CMake
# reconfigured, and every DbgPrint then emitted garbage instead of text
set(SEED_VALUE 20261017)

# Generate seed.h with the SEED macro in the source tree: Crypt.cpp includes "seed.h" from its own
# directory, so the header must live next to it (NOT ADDING THIS DOES NOT WORK)
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/seed.h" "#pragma once\n#define SEED ${SEED_VALUE}\n")

# Compile variant switch: utils.h keeps print() out of builds without DEBUG. NDEBUG must be gone when
# DEBUG is on (assert consistency). Configuring a debug variant is just -DDEBUG_BUILD=ON, which is how
# the GetPteBase/VerifyPteBase runtime output is inspected
option(DEBUG_BUILD "Compile with print() output enabled" OFF)
if(DEBUG_BUILD)
    set(VARIANT_DEFINES DEBUG)
else()
    set(VARIANT_DEFINES NDEBUG)
endif()

# Mapped-payload profile: nothing may be left standing in the kernel that a checker can diff. The
# dedicated map table is a PTE/PFN audit artifact, so it is compiled out here. MAPPED_SAFE=OFF
# restores the stock behaviour
option(MAPPED_SAFE "Compile the mapped-payload profile: no dedicated map table" ON)
if(MAPPED_SAFE)
    list(APPEND VARIANT_DEFINES NO_MAP_TABLE)
endif()

# Driver entry point
wdk_add_driver(Driver
        main.cpp
)

# All defines in one place: the shared seed plus the variant switch. _ITERATOR_DEBUG_LEVEL=0 turns the
# STL's debug checks off, which -nostdlib (no CRT) cannot satisfy. VARIANT_DEFINES can arrive from more
# than one option, so collapse duplicates before the list becomes compiler flags
list(REMOVE_DUPLICATES VARIANT_DEFINES)
target_compile_definitions(Driver
        PRIVATE SEED=${SEED_VALUE} ${VARIANT_DEFINES} _ITERATOR_DEBUG_LEVEL=0
)

# Driver-specific codegen and size flags. -Os replaces the vendor -O2 (user choice); everything else here is
# pure size reduction on top of that. Deliberately NOT set here (already from the vendor
# flags): -fno-rtti, -fno-exceptions, -freestanding, stack alignment / protector switches, warning levels
target_compile_options(Driver
        PRIVATE -Os                                   # optimize for size while keeping most of -O2 speed
        PRIVATE -flto                                 # LTO: must be on both the compile and the link side
        PRIVATE -ffunction-sections                   # one section per function...
        PRIVATE -fdata-sections                       # ...and per data item, so the linker can drop the dead ones
        PRIVATE -fno-unwind-tables                    # no unwind tables
        PRIVATE -fno-asynchronous-unwind-tables       # no async unwind info either
        PRIVATE -g0                                   # no debug info at all
        PRIVATE -fno-ident                            # no compiler .ident/.comment decoration
        PRIVATE -falign-functions=1                   # no inter-function alignment padding
        PRIVATE -falign-loops=1                       # no loop padding
                                                      # (clang has no -falign-jumps/-falign-labels here)
)

# Deliberately NOT set here: -nostdlib (vendor link flags), --strip-all covers the rest
target_link_options(Driver
        PRIVATE -Wl,--gc-sections                     # drop the unused per-item sections
        PRIVATE -Wl,--icf=all                         # fold identical code bodies (pairs with LTO)
        PRIVATE -Wl,--strip-all                       # strip all symbol info
        PRIVATE -flto                                 # LTO cross-module optimization at link time
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
                "$<TARGET_FILE:Driver>"
        )
else()
        message(WARNING "Driver.sys will not be signed: needs signtool and the TESTSIGN_PFX_PASSWORD environment variable")
endif()
