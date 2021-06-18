#pragma once

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// disable the byte padding added after data member warning
#pragma warning(disable : 4820)

// disable unreferenced inlined function removed
#pragma warning(disable : 4514)

// TODO: verify
// disable Spectre mitigation warning
#pragma warning(disable : 5045)

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
#include <time.h>
#include <cstddef>
#include <algorithm>
#include <functional>
#include <span>
#include <array>
#include <tuple>

// Utilities implemented in Common.cpp
// This may involve deprecated functionality
std::wstring utf8ToUtf16(const std::string utf8Str);
std::string ConvertWstringToString(const std::wstring in);

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

enum class DerClass
{
   Universal = 0,
   Application = 1,
   ContextSpecific = 2,
   Private = 3
};

enum class DerType
{
   EOC = 0,
   Boolean = 1,
   Integer = 2,
   BitString = 3,
   OctetString = 4,
   Null = 5,
   ObjectIdentifier = 6,
   ObjectDescriptor = 7, // Not used in signing, don't need encoder for now
   External = 8,         // Not used in signing, don't need encoder for now
   Real = 9,             // Not used in signing, don't need encoder for now
   Enumerated = 10,
   EmbeddedPDV = 11,   // Not used in signing, don't need encoder for now
   UTF8String = 12,    // Not used in signing, don't need encoder for now
   RelativeOid = 13,   // Not used in signing, don't need encoder for now
   Reserved1 = 14,     // reserved
   Reserved2 = 15,     // reserved
   Sequence = 16,      // also sequence of
   Set = 17,           // also set of
   NumericString = 18, // Not used in signing, don't need encoder for now
   PrintableString = 19,
   T61String = 20,      // Not used in signing, don't need encoder for now
   TeletexString = 20,  // An alias for T61String
   VideotexString = 21, // Not used in signing, don't need encoder for now
   IA5String = 22,
   UTCTime = 23,
   GeneralizedTime = 24,
   GraphicString = 25, // Not used in signing, don't need encoder for now
   VisibleString = 26,
   GeneralString = 27,   // Not used in signing, don't need encoder for now
   UniversalString = 28, // Not used in signing, don't need encoder for now
   CharacterString = 29, // Not used in signing, don't need encoder for now
   BMPString = 30,
   Constructed = 0x20,
   ConstructedSequence = Constructed | Sequence,
   ConstructedSet = Constructed | Set
};
