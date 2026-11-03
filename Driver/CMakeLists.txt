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

# Channel selection: the default is the stealth Postbox build (timer/work-item
# mailbox). Set POSTBOX_CHANNEL=OFF for the legacy named-section/system-thread
# channel in Channel.cpp (then also set MANUAL_MAP_ONLY=OFF).
option(POSTBOX_CHANNEL "Use the timer/work-item Postbox channel instead of the named section" ON)
if(POSTBOX_CHANNEL)
    list(APPEND VARIANT_DEFINES POSTBOX_CHANNEL)
endif()

# Manual-map-only profile: the Postbox build is never loaded by SCM. Exclude the
# loader trace cleaners (Traces.cpp) and the hide/relink code (Hide.cpp), and stub
# DriverExit to stop the timer and unlink the map table only. This removes dead
# cleaner/lineage code from the mapped image.
option(MANUAL_MAP_ONLY "Build a manual-map-only driver (requires POSTBOX_CHANNEL)" ON)
if(MANUAL_MAP_ONLY)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "MANUAL_MAP_ONLY requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES MANUAL_MAP_ONLY)
endif()

# NMI gate: constructed-IDT NMI self-test gate. Test-only, default OFF, never
# part of the shipped build. The chain path is assembly-only and was validated
# live: 20,007 chained accounted NMIs under a syscall-dense workload with no
# bugcheck. It remains an IDT hook (IDTR/constructed table observable, and
# PatchGuard may check the IDT), so the product keeps the stock Windows IDT.
option(POSTBOX_NMI "Test-only constructed-IDT NMI gate" OFF)
set(POSTBOX_NMI_SOURCES)
if(POSTBOX_NMI)
    if(NOT POSTBOX_CHANNEL)
        message(FATAL_ERROR "POSTBOX_NMI requires POSTBOX_CHANNEL=ON")
    endif()
    list(APPEND VARIANT_DEFINES POSTBOX_NMI)
    list(APPEND POSTBOX_NMI_SOURCES PostboxNmi.S)
endif()

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
# Shipped NMI-stealth mitigation; forced OFF only when the channel is absent.
include(CMakeDependentOption)
cmake_dependent_option(NMI_SANITIZE "Sanitize external NMI detector samples" ON "POSTBOX_CHANNEL" OFF)
if(NMI_SANITIZE)
    list(APPEND VARIANT_DEFINES NMI_SANITIZE)
endif()

# Pre-callback ordering: a PASSIVE monitor re-registers the sanitizer callback
# at the head of KiNmiCallbackListHead while the detector is active, so the
# frame trampoline runs before the detector's own callback. Shipped NMI-stealth
# mitigation; forced OFF when the sanitizer is absent.
cmake_dependent_option(NMI_FRAME_FIRST "Pre-callback NMI frame ordering" ON "NMI_SANITIZE" OFF)
if(NMI_FRAME_FIRST)
    list(APPEND VARIANT_DEFINES NMI_FRAME_FIRST)
endif()

# Call-site stack spoof: MmCopyVirtualMemory and the intra-image wrappers use a
# fake/shadow return-address frame whose visible return is an nt gadget. This is
# a shipped mitigation now; STACK_PROBE is the test-only in-driver probe that
# exercises it. STACK_SPOOF depends on the NMI sanitizer's nt gadget finder.
cmake_dependent_option(STACK_SPOOF "Call-site stack spoof (return-address shadow)" ON "NMI_SANITIZE" OFF)
if(STACK_SPOOF)
    list(APPEND VARIANT_DEFINES STACK_SPOOF)
endif()

# Test-only in-driver stack probe: records the visible return slots and the
# shadow frame for the channel suite. Never part of the shipped build.
option(STACK_PROBE "Test-only in-driver stack probe" OFF)
if(STACK_PROBE)
    if(NOT STACK_SPOOF)
        message(FATAL_ERROR "STACK_PROBE requires STACK_SPOOF=ON")
    endif()
    list(APPEND VARIANT_DEFINES STACK_PROBE)
endif()

# One-shot + jittered timer: the timer is armed with a due time of PeriodMs plus an
# rdtsc-derived jitter and re-armed from the DPC with an explicit running/generation
# double-check, so _KTIMER.Period stays 0 and the timer table carries no fixed
# polling-period signature. Shipped timer-signature stealth; forced OFF only when
# the channel is absent.
cmake_dependent_option(POSTBOX_ONESHOT_TIMER "Arm the Postbox timer one-shot with jitter, re-armed from the DPC" ON "POSTBOX_CHANNEL" OFF)
if(POSTBOX_ONESHOT_TIMER)
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
    if(STACK_SPOOF)
        list(APPEND POSTBOX_REAPER_SOURCES PostboxStackSpoof.S)
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
option(DRIVER_SIGNING "Sign Driver.sys with TestSign.pfx when the password is set" OFF)
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

# Deployment guard: STEALTH_PROFILE=ON fails the configure unless every switch that
# scans back is in its shipped state, so a lab variant can never be mistaken for a
# deployment build. Lab experiments leave it off and configure normally.
option(STEALTH_PROFILE "Fail the configure unless this is a stealth deployment build" ON)
if(STEALTH_PROFILE)
    if(DEBUG_BUILD)
        message(FATAL_ERROR "STEALTH_PROFILE=ON requires DEBUG_BUILD=OFF (print() is a shipped-image giveaway)")
    endif()
    if(NOT POSTBOX_CHANNEL OR NOT MANUAL_MAP_ONLY OR NOT MAPPED_SAFE)
        message(FATAL_ERROR "STEALTH_PROFILE=ON requires POSTBOX_CHANNEL=ON, MANUAL_MAP_ONLY=ON, MAPPED_SAFE=ON")
    endif()
    if(NOT NMI_SANITIZE OR NOT STACK_SPOOF OR NOT NMI_FRAME_FIRST OR NOT POSTBOX_ONESHOT_TIMER)
        message(FATAL_ERROR "STEALTH_PROFILE=ON requires NMI_SANITIZE=ON, STACK_SPOOF=ON, NMI_FRAME_FIRST=ON and POSTBOX_ONESHOT_TIMER=ON (shipped mitigations)")
    endif()
    foreach(_Probe T2_PROBE E3_DPC_PROBE NMI_PROBE STACK_PROBE POSTBOX_NMI)
        if(${_Probe})
            message(FATAL_ERROR "STEALTH_PROFILE=ON forbids ${_Probe} (test build)")
        endif()
    endforeach()
    if(DRIVER_SIGNING)
        message(FATAL_ERROR "STEALTH_PROFILE=ON requires DRIVER_SIGNING=OFF (a manual-map payload carries no signature)")
    endif()
endif()
