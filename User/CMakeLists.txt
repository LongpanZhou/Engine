cmake_minimum_required(VERSION 3.22)
project(User)

set(CMAKE_CXX_STANDARD 23)

function(add_engine_client target)
    add_executable(${target} ${ARGN})

    target_compile_options(${target} PRIVATE
            -O3                       # Optimize for speed
            -march=native             # Use native CPU features (use cautiously if distributing binaries)
            -flto                     # Enable Link-Time Optimization
            -ffunction-sections       # Allow linker to drop unused functions
            -fdata-sections           # Same for data
            -g0                       # Strip debug info
    )

    target_link_options(${target} PRIVATE
            -static-libstdc++         # Statically link libstdc++
            -static-libgcc            # Statically link libgcc
            -flto                     # LTO at link time
            -Wl,--gc-sections         # Remove unused sections
            -s                        # Strip all symbols
    )

    target_link_libraries(${target} PRIVATE bcrypt)
endfunction()

# Dual-client lab harness: old EngineCiShared client plus --postbox.
add_engine_client(User main.cpp PostboxClient.cpp)

# Client-only deployment binary: no EngineCiShared/ECI1 strings.
add_engine_client(PostboxClient PostboxOnly.cpp PostboxClient.cpp)
target_compile_options(PostboxClient PRIVATE -fno-exceptions -fno-rtti)
