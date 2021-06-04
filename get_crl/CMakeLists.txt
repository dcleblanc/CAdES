cmake_minimum_required (VERSION 3.13)
project( get_crl )
add_executable(get_crl get_crl.cpp )
target_link_libraries( get_crl CAdESLib )