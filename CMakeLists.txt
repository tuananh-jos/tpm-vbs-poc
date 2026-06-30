cmake_minimum_required(VERSION 3.10)
project(tpm_vbs_poc CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path to the TSS.MSR/TSS.CPP source tree (must be built first; see README).
set(TSS_CPP "${CMAKE_CURRENT_SOURCE_DIR}/../TSS.MSR/TSS.CPP"
    CACHE PATH "Path to the built TSS.MSR/TSS.CPP directory")

# Static archive produced by `make config=release` (use tssd.a for a debug build).
set(TSS_ARCHIVE "${TSS_CPP}/bin/tss.a"
    CACHE FILEPATH "TSS.CPP static archive")

find_package(OpenSSL REQUIRED)

add_executable(vbs_poc vbs_poc.cpp)
target_include_directories(vbs_poc PRIVATE "${TSS_CPP}/include")
target_link_libraries(vbs_poc PRIVATE
    "${TSS_ARCHIVE}"
    OpenSSL::Crypto
    ${CMAKE_DL_LIBS})

# pthread on POSIX
find_package(Threads REQUIRED)
target_link_libraries(vbs_poc PRIVATE Threads::Threads)
