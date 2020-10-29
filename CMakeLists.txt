cmake_minimum_required(VERSION 3.14)
project(ptrace_utils)

add_library(ptrace_utils SHARED src/ptrace_utils.c  src/syscalls.c)
target_include_directories(ptrace_utils PUBLIC include)

set(CMAKE_INSTALL_PREFIX "/usr")

install(
    TARGETS ptrace_utils
    LIBRARY DESTINATION lib64
)

install(
    FILES include/ptrace_utils.h
    DESTINATION include
)

install(
    FILES src/ptrace_utils.py
    DESTINATION lib/python3/dist-packages
)
