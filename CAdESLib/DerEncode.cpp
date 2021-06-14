// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "DerEncode.h"
#include "Common.h"
#include "CAdES.h"
#include "DerDecode.h"

void EncodeHelper::EncodeSize(size_t size, std::span<std::byte> out)
{
	// When size fits within a byte and does not have its high bit set, encode it directly
	if (size <= 0x7f)
	{
		if (out.size() < 1)
		{
			throw std::out_of_range("Target output buffer must have space for at least one byte");
		}
		out[0] = static_cast<std::byte>(size);
		return;
	}

	// Otherwise the first byte is the number of following big-endian, non-zero bytes
	size_t requiredLength = 1;
	for (auto tempSize = size; tempSize > 0; tempSize >>= 8)
	{
		requiredLength++;
	}

	if (out.size() < requiredLength)
	{
		throw std::out_of_range("Target output buffer must have space for encoding 1 + the total used bytes in big-endian order");
	}

	// Set the high bit to indicate the lower bits contain the required number of bytes
	out[0] = static_cast<std::byte>(0x80 | requiredLength);

	// start and the end of the required span and 
	auto offset = requiredLength - 1;
	for (auto tempSize = size; tempSize > 0; tempSize >>= 8)
	{
		out[offset] = static_cast<std::byte>(tempSize & 0xFF);
		offset--;
	}
}
