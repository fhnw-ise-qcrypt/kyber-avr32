cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_COMPILER avr32-gcc)
set(CMAKE_CXX_COMPILER avr32-g++)
set(CMAKE_ASM_COMPILER avr32-gcc)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(kyber C ASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

enable_testing()

#find_package(OpenSSL REQUIRED)
#include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(ref)
#add_subdirectory(avx2)
