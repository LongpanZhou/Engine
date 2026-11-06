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

# DEBUG_BUILD enables print(); the default build is the stealth release.
option(DEBUG_BUILD "Compile with print() output enabled" OFF)

set(VARIANT_DEFINES)
if(DEBUG_BUILD)
    list(APPEND VARIANT_DEFINES DEBUG)
else()
    list(APPEND VARIANT_DEFINES NDEBUG)
endif()

# Job-only build: no persistent channel, PBOX config, mailbox, timer/DPC, work
# item, NMI sanitizer, stack spoof, or reaper. The batch runs inline in the
# loader entry and the image is freed afterwards, so there is no resident
# driver-side object. The persistent profile below remains the default.
option(POSTBOX_JOB_ONLY "Job-only batch driver (no persistent channel)" OFF)
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
# The zero-thread product path does not use the preserved APC-stackwalk
# thread loop, its start-address spoof, or the thread create/close imports.
# Keep them available for test builds, but never in the stealth image.
option(POSTBOX_KEEP_THREAD_SPOOF "Test-only legacy thread-spoof code" OFF)
# The product has no backed NMI callback routine. Registering the mapped
# PostboxNmiSanitizeEntry would put an unbacked pointer in
# nt!KiNmiCallbackListHead, so the sanitizer fails closed unless a test build
# explicitly opts into the old mapped-callback path.
option(POSTBOX_NMI_ALLOW_MAPPED_CALLBACK "Test-only mapped NMI callback" OFF)
# The product refuses mid-function nt jmp-[rcx]/jmp-[rdx] gadgets: a strict
# .pdata validator can flag them even though the opcode is in a module. The
# test-only switch restores the old behaviour for lab runs on builds where no
# function-entry thunk exists.
option(POSTBOX_ALLOW_MID_FUNCTION_GADGETS "Test-only mid-function nt gadgets" OFF)
# Product exact-entry event start. Uses nt!KiUmsRestoreUch as the
# PsCreateSystemThread start routine, starts the event thread at driver start,
# and drops the runtime work item/timer dispatch. OFF restores the old
# timer/DPC/work-item fallback (the fd704aa behaviour).
option(POSTBOX_EVENT_START "Exact-entry event thread start (product default)" ON)

# The job-only image deliberately has no Postbox state page, NMI machinery, or
# stack-spoof trampolines. Refuse probe/NMI combinations instead of compiling a
# job-only image that silently depends on the persistent code. POSTBOX_EVENT_START
# is a persistent-channel switch and is intentionally ignored here; it does not
# contribute code to the job-only build.
if(POSTBOX_JOB_ONLY)
    foreach(_Probe POSTBOX_NMI T2_PROBE E3_DPC_PROBE NMI_PROBE STACK_PROBE
                   POSTBOX_KEEP_THREAD_SPOOF POSTBOX_NMI_ALLOW_MAPPED_CALLBACK
                   POSTBOX_ALLOW_MID_FUNCTION_GADGETS)
        if(${_Probe})
            message(FATAL_ERROR "POSTBOX_JOB_ONLY cannot be combined with ${_Probe}")
        endif()
    endforeach()
endif()

set(POSTBOX_NMI_SOURCES)
if(POSTBOX_NMI)
    list(APPEND VARIANT_DEFINES POSTBOX_NMI)
    list(APPEND POSTBOX_NMI_SOURCES PostboxNmi.S)
endif()
# Job batch mode: one map, one entry, N jobs, one teardown. Enables POSTBOX_JOB.
# POSTBOX_JOB_ONLY is the channel-free profile; this option alone keeps the
# persistent build.
option(POSTBOX_JOB "Job batch mode (POSTBOX_JOB)" OFF)
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
if(POSTBOX_KEEP_THREAD_SPOOF)
    list(APPEND VARIANT_DEFINES POSTBOX_KEEP_THREAD_SPOOF)
endif()
if(POSTBOX_NMI_ALLOW_MAPPED_CALLBACK)
    list(APPEND VARIANT_DEFINES POSTBOX_NMI_ALLOW_MAPPED_CALLBACK)
endif()
if(POSTBOX_ALLOW_MID_FUNCTION_GADGETS)
    list(APPEND VARIANT_DEFINES POSTBOX_ALLOW_MID_FUNCTION_GADGETS)
endif()
# The job-only image never consumes this persistent-channel define.
if(POSTBOX_EVENT_START AND NOT POSTBOX_JOB_ONLY)
    list(APPEND VARIANT_DEFINES POSTBOX_EVENT_START)
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
target_compile_options(Driver PRIVATE
        -Os
        -flto
        -ffunction-sections
        -fdata-sections
        -fno-unwind-tables
        -fno-asynchronous-unwind-tables
        -g0
        -fno-ident
        -falign-functions=1
        -falign-loops=1
)

target_link_options(Driver PRIVATE
        -Wl,--subsystem,native
        -Wl,--gc-sections
        -Wl,--icf=all
        -Wl,--strip-all
        -flto
)
