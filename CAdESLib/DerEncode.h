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
	for (auto i : in)
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

	template <typename T>
	static void EncodeSetOrSequenceOf(DerType type, std::vector<T> &in, std::span<std::byte> out)
	{
		size_t cbInternal = 0;
		size_t offset = 0;

		if (in.size() == 0)
		{
			if (out.size() < 2)
				throw std::overflow_error("Overflow in EncodeSetOrSequenceOf");

			out[0] = static_cast<std::byte>(DerType::Null);
			out[1] = std::byte{0};
			return;
		}

		out[0] = static_cast<std::byte>(type);

		size_t cbVector = GetEncodedSize(in);

		offset = 1;
		EncodeSize(cbVector, out.subspan(offset));
		offset += cbInternal;

		for (uint32_t i = 0; i < in.size(); ++i)
		{
			in[i].Encode(out.subspan(offset));
			offset += cbInternal;
		}
	}
	template <typename T>
	static void EncodeString(DerType type, std::basic_string<T> in, std::span<std::byte> out)
	{
		// If it is empty, encode as Null
		if (in.size() == 0)
		{
			if (out.size() < 2)
				throw std::overflow_error("Overflow in EncodeString");

			out[0] = static_cast<std::byte>(DerType::Null);
			out[1] = std::byte{0};
			return;
		}

		const size_t charSize = sizeof(T);
		size_t cbNeeded = (in.size() + 1) * charSize; // Data, plus tag
		std::byte encodedSize[sizeof(int64_t)];

		EncodeSize(in.size() * charSize, encodedSize);

		// Note - cbDataSize guaranteed to be <= 8, int32_t overflow not possible
		// cbNeeded += cbData;

		if (cbNeeded > out.size())
			throw std::length_error("Insufficient Buffer");

		out[0] = static_cast<std::byte>(type);
		// size_t offset = 1;
		// memcpy_s(out.data() + offset, out.size() - offset, encodedSize, cbData);
		// offset += cbData;
		// memcpy_s(out.data() + offset, out.size() - offset, &in[0], in.size() * charSize);

		// cbData = offset + in.size() * charSize;
		return;
	}

	static void EncodeVector(DerType type, const std::span<const std::byte> in, std::span<std::byte> out)
	{
		// If it is empty, encode as Null
		if (in.size() == 0)
		{
			if (out.size() < 2)
				throw std::overflow_error("Overflow in EncodeVector");

			out[0] = static_cast<std::byte>(DerType::Null);
			out[1] = std::byte{0};
			return;
		}

		size_t cbDataSize = 0;
		size_t cbNeeded = in.size() + 1; // Data, plus tag
		std::byte encodedSize[sizeof(int64_t)];

		EncodeSize(in.size(), std::span{encodedSize});

		// Note - cbDataSize guaranteed to be <= 8, int overflow not possible
		cbNeeded += cbDataSize;

		if (cbNeeded > out.size())
			throw std::length_error("Insufficient Buffer");

		out[0] = static_cast<std::byte>(type);
		size_t offset = 1;
		memcpy_s(out.data() + offset, out.size() - offset, &encodedSize, cbDataSize);
		offset += cbDataSize;
		memcpy_s(out.data() + offset, out.size() - offset, &in[0], in.size());
		return;
	}

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
