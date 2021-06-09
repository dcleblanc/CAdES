#pragma once

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// disable the byte padding added after data member warning
#pragma warning(disable : 4820)

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
#include <functional>

// Utilities implemented in Common.cpp
// This may involve deprecated functionality
std::wstring utf8ToUtf16(const std::string& utf8Str);
void ConvertWstringToString(const std::wstring& in, std::string& out);

#ifndef _WIN32
#include <cstdarg>

// Safe CRT functions not present in Linux
int32_t memcpy_s(
   void *dest,
   size_t destSize,
   const void *src,
   size_t count
);

int32_t gmtime_s(
   struct tm* tmDest,
   const std::time_t* sourceTime
);

int32_t sprintf_s(
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
#include <cstddef>
#include <array>
#include <span>

// Once there is more to it, move these to a header 
// that can be used to abstract out platform crypto differences
bool HashVectorSha1(const std::vector<std::byte>& data, std::vector<std::byte>& out);
bool HashVectorSha256(const std::vector<std::byte>& data, std::vector<std::byte>& out);

template <typename... Ts>
std::array<std::byte, sizeof...(Ts)> make_bytes(Ts &&...args) noexcept
{
   return {std::byte(std::forward<Ts>(args))...};
}

template <typename T, typename... Ts>
constexpr std::array<T, 1 + sizeof...(Ts)> make_array(T &&head, Ts &&...tail)
{
   return {{std::forward<T>(head), std::forward<Ts>(tail)...}};
}