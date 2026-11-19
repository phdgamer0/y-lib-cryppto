cmake_minimum_required(VERSION 3.16)
project(y-lib-crypto)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
find_package(OpenSSL REQUIRED)
# y-- source tree to compile against; yenv passes its installed toolchain
set(YLANG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../y---lang" CACHE PATH "y-- source directory")
add_library(y-crypto SHARED module.cpp hash-library/md5.cpp hash-library/sha1.cpp hash-library/sha256.cpp hash-library/sha3.cpp hash-library/keccak.cpp)
# symbols come from the ymm process at load time
if(APPLE)
    target_link_options(y-crypto PRIVATE -undefined dynamic_lookup)
endif()
target_include_directories(y-crypto PRIVATE ${YLANG_DIR}/include ${YLANG_DIR}/include/ylang ${YLANG_DIR}/src)
target_link_libraries(y-crypto PRIVATE OpenSSL::SSL OpenSSL::Crypto)
