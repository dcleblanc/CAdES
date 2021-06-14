// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include "Common.h"

template <typename T>
size_t GetEncodedSize(std::vector<T> &in) // Non-const reference, because EncodedSize will set cbData
{
	size_t ret = GetDataSize(in);

	if (ret == 0)
		return 2;

	return ret;
}

template <typename T>
size_t GetDataSize(std::vector<T> &in)
{
	size_t ret = 0;
	for(auto i: in)
	{ 
		ret += i.EncodedSize();
	}
	return ret;
}

class EncodeHelper
{
public:
	EncodeHelper(std::span<std::byte> out) : out(out) {}

	EncodeHelper &operator=(const EncodeHelper) = delete;
	~EncodeHelper() = default;

	void Init(size_t _cbNeeded, std::byte type)
	{
		cbNeeded = _cbNeeded;
		if (cbNeeded > out.size() || out.size() < 2)
			throw std::overflow_error("Overflow in Encode");

		// Set the type
		out[0] = type;
		offset = 1;

		EncodeSize(cbNeeded, DataPtr(out));
	}

	static void EncodeSize(size_t size, std::span<std::byte> out);

	// void CheckExit()
	// {
	// 	if (offset != cbNeeded)
	// 		throw std::runtime_error("Size needed not equal to size used");
	// 	// std::cout << "Size needed not equal to size used" << std::endl;
	// }

	std::span<std::byte> DataPtr(std::span<std::byte> in) const
	{
		return in.subspan(offset);
	}

	size_t DataSize()
	{
		if (offset > cbNeeded)
			throw std::overflow_error("Integer overflow in data size");

		return cbNeeded - offset;
	}

	size_t &CurrentSize() { return cbCurrent; }

private:
	std::span<std::byte> out;
	size_t offset;
	size_t cbNeeded;
	size_t cbCurrent;
};
