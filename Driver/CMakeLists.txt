cmake_minimum_required(VERSION 3.22)
project(Driver)

# Language standard: 23 comes from wdk_add_driver (CXX_STANDARD 23 + REQUIRED).
set(CMAKE_CXX_EXTENSIONS OFF)

# crosswdk supplies the WDK libraries, kernel build flags, and linker entry point.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/")
find_package(CrossWDK REQUIRED)

# Fixed seed: the compile-time encoder and runtime decoder must agree.
set(SEED_VALUE 20261017)
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/seed.h"
     "#pragma once\n#define SEED ${SEED_VALUE}\n")

# The only build switch: Debug enables print(); Build is the stealth release.
option(DEBUG_BUILD "Compile with print() output enabled" OFF)

set(VARIANT_DEFINES)
if(DEBUG_BUILD)
    list(APPEND VARIANT_DEFINES DEBUG)
else()
    list(APPEND VARIANT_DEFINES NDEBUG)
endif()

# F1 job-only: no persistent channel, PBOX config, mailbox, timer/DPC, work
# item, NMI sanitizer, stack spoof, or reaper. Test-only; the product build
# below keeps the stealth profile.
option(POSTBOX_JOB_ONLY "Test-only F1 job-only driver (no persistent channel)" OFF)
if(POSTBOX_JOB_ONLY)
    list(APPEND VARIANT_DEFINES
            POSTBOX_JOB
            POSTBOX_JOB_ONLY
            NO_MAP_TABLE
            MANUAL_MAP_ONLY)
else()
    # The stealth deployment profile is unconditional. These are not options: a
    # non-stealth build is not a supported product configuration.
    list(APPEND VARIANT_DEFINES
            NO_MAP_TABLE          # no dedicated PTE/map table
            POSTBOX_CHANNEL       # timer/work-item mailbox channel
            MANUAL_MAP_ONLY       # no SCM/loader-entry path
            NMI_SANITIZE          # NMI sample sanitizer
            NMI_FRAME_FIRST       # sanitizer runs before the detector callback
            STACK_SPOOF           # call-site return-address shadow
            POSTBOX_ONESHOT_TIMER # jittered one-shot timer, no fixed period
    )
endif()

# Lab-only probes. All default OFF and none is part of the stealth profile: a
# probe reproduces a detection experiment on a test VM, it does not add stealth.
# The feature defines above stay unconditional whether a probe is on or off.
option(POSTBOX_NMI "Test-only constructed-IDT NMI gate" OFF)
option(T2_PROBE "Test-only CPU-1 stale-TLB probe around KeIpiGenericCall" OFF)
option(E3_DPC_PROBE "Test-only DPC-based CPU-1 stale-TLB probe" OFF)
option(NMI_PROBE "Test-only NMI callback RIP/RSP probe" OFF)
option(STACK_PROBE "Test-only in-driver stack probe" OFF)

set(POSTBOX_NMI_SOURCES)
if(POSTBOX_NMI)
    list(APPEND VARIANT_DEFINES POSTBOX_NMI)
    list(APPEND POSTBOX_NMI_SOURCES PostboxNmi.S)
endif()
# F1 Job-post: one map, one entry, N jobs, one teardown. Test-only; the
# deployment build leaves it OFF.
option(POSTBOX_JOB "Test-only F1 job-post batch mode" OFF)
if(POSTBOX_JOB)
    list(APPEND VARIANT_DEFINES POSTBOX_JOB)
endif()
if(T2_PROBE)
    list(APPEND VARIANT_DEFINES T2_PROBE)
endif()
if(E3_DPC_PROBE)
    # The E3 result block has a fixed KD offset in the standalone probe layout;
    # NMI_PROBE grows PostboxState, so the two experiments cannot share a build.
    if(NMI_PROBE)
        message(FATAL_ERROR "E3_DPC_PROBE cannot be combined with NMI_PROBE")
    endif()
    list(APPEND VARIANT_DEFINES E3_DPC_PROBE)
endif()
if(NMI_PROBE)
    list(APPEND VARIANT_DEFINES NMI_PROBE)
endif()
if(STACK_PROBE)
    list(APPEND VARIANT_DEFINES STACK_PROBE)
endif()

# The persistent build needs the reaper/NMI/stack-spoof assembly. The job-only
# build has none of those mechanisms, so it links only main.cpp.
set(DRIVER_SOURCES main.cpp)
if(NOT POSTBOX_JOB_ONLY)
    enable_language(ASM)
    list(APPEND DRIVER_SOURCES
            ${POSTBOX_NMI_SOURCES}
            PostboxReaper.S
            PostboxNmiEntry.S
            PostboxStackSpoof.S)
endif()
wdk_add_driver(Driver ${DRIVER_SOURCES})

list(REMOVE_DUPLICATES VARIANT_DEFINES)
target_compile_definitions(Driver
        PRIVATE SEED=${SEED_VALUE} ${VARIANT_DEFINES} _ITERATOR_DEBUG_LEVEL=0
)

# Size/codegen flags. The vendor already supplies -O3; -Os replaces it.
target_compile_options(Driver
        PRIVATE -Os
        PRIVATE -flto
        PRIVATE -ffunction-sections
        PRIVATE -fdata-sections
        PRIVATE -fno-unwind-tables
        PRIVATE -fno-asynchronous-unwind-tables
        PRIVATE -g0
        PRIVATE -fno-ident
        PRIVATE -falign-functions=1
        PRIVATE -falign-loops=1
)

target_link_options(Driver
        PRIVATE -Wl,--subsystem,native
        PRIVATE -Wl,--gc-sections
        PRIVATE -Wl,--icf=all
        PRIVATE -Wl,--strip-all
        PRIVATE -flto
)
