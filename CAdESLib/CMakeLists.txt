cmake_minimum_required (VERSION 3.13)
project( CAdESLib )
add_library( CAdESLib CAdES.cpp CMSSignature.cpp Common.cpp DerEncode.cpp DerTypes.cpp Oids.cpp )


