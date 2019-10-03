cmake_minimum_required (VERSION 2.6)
project( CAdESLib )
set (CMAKE_CXX_FLAGS "-Wall --std=c++11")
add_library( CAdESLib CAdES.cpp CMSSignature.cpp Common.cpp DerEncode.cpp DerTypes.cpp Oids.cpp )


