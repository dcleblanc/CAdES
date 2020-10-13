cmake_minimum_required (VERSION 2.6)
project( CAdESLib )
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()
add_library( CAdESLib CAdES.cpp CMSSignature.cpp Common.cpp DerEncode.cpp DerTypes.cpp Oids.cpp )


