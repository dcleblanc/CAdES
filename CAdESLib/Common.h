#pragma once

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <string>
#include <set>
#include <vector>
#include <memory>
#include <type_traits>
#include <locale>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <assert.h>
#include <time.h>
#include <cstring>
#include <cstddef>
#include <algorithm>

// Utilities implemented in Common.cpp
// This may involve deprecated functionality
std::wstring utf8ToUtf16(const std::string& utf8Str);
void ConvertWstringToString(const std::wstring& in, std::string& out);

#ifndef _WIN32
#include <cstdarg>

// Safe CRT functions not present in Linux
int memcpy_s(
   void *dest,
   size_t destSize,
   const void *src,
   size_t count
);

int gmtime_s(
   struct tm* tmDest,
   const std::time_t* sourceTime
);

int sprintf_s(
   char *buffer,
   size_t sizeOfBuffer,
   const char *format,
   ...
);

#define _countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif

#include "Oids.h"
#include "DerTypes.h"
#include "DerEncode.h"
#include "CAdES.h"
#include "CMSSignature.h"

// Once there is more to it, move these to a header 
// that can be used to abstract out platform crypto differences
bool HashVectorSha1(const std::vector<unsigned char>& data, std::vector<unsigned char>& out);
bool HashVectorSha256(const std::vector<unsigned char>& data, std::vector<unsigned char>& out);


