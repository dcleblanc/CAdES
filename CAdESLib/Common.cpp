// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined _WIN32
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#endif

#include "Common.h"
// This lives here, not in Common.h because it has its own warning behavior for the functions below
#include <codecvt>

static const int lib_version = 0x0100;
// Define something so that the linker won't complain about no public symbols from this compilation unit
int get_version() { return lib_version; }

// Also put some conversion utilities here

std::wstring utf8ToUtf16(const std::string& utf8Str)
{
	// We don't expect any really interesting utf8 characters
	// Try doing this cheaply
	std::wstring out;
	out.reserve(utf8Str.length());

	for (char c : utf8Str)
	{
		out += (static_cast<wchar_t>(c));
	}

	return out;
	/*
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
	return conv.from_bytes(utf8Str);
	*/
}

void ConvertWstringToString(const std::wstring& in, std::string& out)
{
	// It appears that this may be deprecated at some point
	// see https://stackoverflow.com/questions/42946335/deprecated-header-codecvt-replacement
	// It currently creates warnings, and may need to be replaced with platform-specific code

	// setup converter
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;

	// use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
	out = converter.to_bytes(in);
}

#ifndef _WIN32
int memcpy_s( void *dest, size_t destSize, const void *src, size_t count )
{
	if( destSize < count )
		return ERANGE;

	memcpy(dest, src, count);
	return 0;
}

int gmtime_s( struct tm* tmDest, const std::time_t* sourceTime )
{
	if( tmDest == nullptr )
		return EINVAL;

	if( sourceTime == nullptr || *sourceTime < 0 )
	{
		std::memset(tmDest, 0xff, sizeof(tm));
		return EINVAL;
	}

	tmDest = gmtime( sourceTime );
	return 0;
}

int sprintf_s( char *buffer, size_t sizeOfBuffer, const char *format, ... )
{
    int retval;
    va_list ap;

	if( buffer == nullptr || format == nullptr)
	{
		errno = EINVAL;
		return -1;
	}

    va_start(ap, format);
    retval = vsnprintf(buffer, sizeOfBuffer, format, ap);
    va_end(ap);

	if( retval < 0 || static_cast<size_t>(retval) >= sizeOfBuffer )
		retval = -1;

    return retval;
}
#endif
