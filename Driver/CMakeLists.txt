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

# Channel selection: the default is the named-section/system-thread channel in Channel.cpp.
# POSTBOX_CHANNEL replaces it with the timer/work-item mailbox (AC-25). The Postbox build is
# manual-map only: the entry's second argument is a PostboxConfig, not a provider image name.
option(POSTBOX_CHANNEL "Use the timer/work-item Postbox channel instead of the named section" OFF)
if(POSTBOX_CHANNEL)
    list(APPEND VARIANT_DEFINES POSTBOX_CHANNEL)
endif()

# Manual-map-only profile: the Postbox build is never loaded by SCM. Exclude the
# loader trace cleaners (Traces.cpp) and the hide/relink code (Hide.cpp), and stub
# DriverExit to stop the timer and unlink the map table only. This removes dead
# cleaner/lineage code from the mapped image.
option(MANUAL_MAP_ONLY "Build a manual-map-only driver (requires POSTBOX_CHANNEL)" OFF)
if(MANUAL_MAP_ONLY)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "MANUAL_MAP_ONLY requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES MANUAL_MAP_ONLY)
endif()

# NMI gate: disabled. The constructed-IDT gate (PostboxNmi.S) is retained as
# historical test code, but it is not a supported build: on Windows 10 19041 its
# chain path can corrupt the interrupted thread's MXCSR save slot and bugcheck
# 0x3B (0xC0000005) in KiSystemServiceExit. The default Postbox build keeps the
# stock Windows IDT and has no NMI/IDT-hook artifact.
option(POSTBOX_NMI "Unsupported: constructed-IDT NMI gate (disabled)" OFF)
if(POSTBOX_NMI)
    message(FATAL_ERROR "POSTBOX_NMI is disabled: the constructed-IDT gate caused "
                        "0x3B (0xC0000005) stack corruption on 19041; use the plain "
                        "Postbox build")
endif()
set(POSTBOX_NMI_SOURCES)

# Test-only E3 probe: around the product KeIpiGenericCall, write to the .text
# probe page from CPU 1 and record whether the stale RW TLB entry survived.
# Never part of the shipped build.
option(T2_PROBE "Test-only CPU-1 stale-TLB probe around KeIpiGenericCall" OFF)
if(T2_PROBE)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "T2_PROBE requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES T2_PROBE)
endif()

# Test-only E3 DPC probe: a CPU-1-targeted DPC remaps a test page's PTE and
# records the stale read before the product KeIpiGenericCall flush and the
# flushed read after it. Never part of the shipped build.
option(E3_DPC_PROBE "Test-only DPC-based CPU-1 stale-TLB probe" OFF)
if(E3_DPC_PROBE)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "E3_DPC_PROBE requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES E3_DPC_PROBE)
endif()

# Test-only NMI callback probe: KeRegisterNmiCallback + HalSendNMI to every
# core, record the interrupted machine frame, and check RIP against
# PsLoadedModuleList. Never part of the shipped build.
option(NMI_PROBE "Test-only NMI callback RIP/RSP probe" OFF)
if(NMI_PROBE)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "NMI_PROBE requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES NMI_PROBE)
endif()

# NMI sample sanitizer: register an NMI callback that runs after an external
# detector's callback and rewrites the detector's recorded RIP to a valid
# loaded-module address. Callback-list only: no IDT/TSS/SSDT or code hooks.
option(NMI_SANITIZE "Sanitize external NMI detector samples" OFF)
if(NMI_SANITIZE)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "NMI_SANITIZE requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES NMI_SANITIZE)
endif()

# One-shot + jittered timer: the timer is armed with a due time of PeriodMs plus an
# rdtsc-derived jitter and re-armed from the DPC with an explicit running/generation
# double-check, so _KTIMER.Period stays 0 and the timer table carries no fixed
# polling-period signature. OFF keeps the stock periodic arm.
option(POSTBOX_ONESHOT_TIMER "Arm the Postbox timer one-shot with jitter, re-armed from the DPC" OFF)
if(POSTBOX_ONESHOT_TIMER)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "POSTBOX_ONESHOT_TIMER requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES POSTBOX_ONESHOT_TIMER)
endif()

# Self-free reaper: the terminal work routine creates a system thread whose entry
# is an assembly stub in the image. The stub tail-jumps to MmFreeIndependentPages,
# so the free returns to PspSystemThreadStartup and no image instruction is fetched
# after the image is released. Only the Postbox build has this lifetime model.
set(POSTBOX_REAPER_SOURCES)
if(POSTBOX_CHANNEL)
    enable_language(ASM)
    list(APPEND POSTBOX_REAPER_SOURCES PostboxReaper.S)
    if(NMI_SANITIZE)
        list(APPEND POSTBOX_REAPER_SOURCES PostboxNmiEntry.S)
    endif()
endif()

# Driver entry point
wdk_add_driver(Driver
        main.cpp
        ${POSTBOX_NMI_SOURCES}
        ${POSTBOX_REAPER_SOURCES}
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
        PRIVATE -Wl,--subsystem,native                # a driver is a native image, not a console EXE
        PRIVATE -Wl,--gc-sections                     # drop the unused per-item sections
        PRIVATE -Wl,--icf=all                         # fold identical code bodies (pairs with LTO)
        PRIVATE -Wl,--strip-all                       # strip all symbol info
        PRIVATE -flto                                 # LTO cross-module optimization at link time
)

# Code signing (optional): finds signtool in any installed Windows Kit, and takes the PFX password from the
# environment instead of storing it in this file. Signing is skipped (with a warning) when either is missing.
# The lab PFX subject names the developer ("WDKTestCert <user>,..."), which is a T7 artifact; a manual-map
# payload does not need a signature, so deployments can configure -DDRIVER_SIGNING=OFF or replace the PFX.
option(DRIVER_SIGNING "Sign Driver.sys with TestSign.pfx when the password is set" ON)
find_program(SIGNTOOL signtool
        PATHS "C:/Program Files (x86)/Windows Kits/10/bin/x86"
              "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x86"
        NO_DEFAULT_PATH)
if(DRIVER_SIGNING AND SIGNTOOL AND DEFINED ENV{TESTSIGN_PFX_PASSWORD})
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
