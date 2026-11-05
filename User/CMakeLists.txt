cmake_minimum_required(VERSION 3.22)
project(PostboxClient)

set(CMAKE_CXX_STANDARD 23)

# The legacy shared-memory default channel client is gone. The product client is
# the Postbox-only build; the loader is built from the repository root.
add_executable(PostboxClient PostboxOnly.cpp PostboxClient.cpp)

target_compile_options(PostboxClient PRIVATE
        -O3                       # Optimize for speed
        -march=native             # Use native CPU features (use cautiously if distributing binaries)
        -flto                     # Enable Link-Time Optimization
        -ffunction-sections       # Allow linker to drop unused functions
        -fdata-sections           # Same for data
        -g0                       # Strip debug info
)

target_link_options(PostboxClient PRIVATE
        -static-libstdc++         # Statically link libstdc++
        -static-libgcc            # Statically link libgcc
        -flto                     # LTO at link time
        -Wl,--gc-sections         # Remove unused sections
        -s                        # Strip all symbols
)
