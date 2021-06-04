cmake_minimum_required (VERSION 3.13)
project(CAdES)
set (CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
add_subdirectory(CAdESLib)
add_subdirectory(get_crl)
add_subdirectory(DumpTlsCerts)

