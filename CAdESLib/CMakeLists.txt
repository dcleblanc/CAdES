cmake_minimum_required (VERSION 3.13)
project( CAdESLib )
add_library( CAdESLib CAdES.cpp CMSSignature.cpp Common.cpp DerDecode.cpp DerEncode.cpp DerTypes.cpp Oids.cpp TestDerTypes.cpp )

set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE True)

