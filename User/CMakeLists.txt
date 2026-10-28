cmake_minimum_required(VERSION 3.22)
project(User)

set(CMAKE_CXX_STANDARD 23)

add_executable(User main.cpp
)

target_compile_options(User PRIVATE
        -O3                       # Optimize for speed
        -march=native             # Use native CPU features (use cautiously if distributing binaries)
        -flto                     # Enable Link-Time Optimization
        -ffunction-sections       # Allow linker to drop unused functions
        -fdata-sections           # Same for data
        -g0                       # Strip debug info
)

target_link_options(User PRIVATE
        -static-libstdc++         # Statically link libstdc++
        -static-libgcc            # Statically link libgcc
        -flto                     # LTO at link time
        -Wl,--gc-sections         # Remove unused sections
        -s                        # Strip all symbols
)