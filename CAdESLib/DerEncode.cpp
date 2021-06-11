// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"
#include "CAdES.h"
#include "DerEncode.h"

void EncodeSize(size_t size, std::span<std::byte> out, size_t &cbUsed)
{
	// When size fits within a byte and does not have its high bit set, encode it directly
	if (size <= 0x7f)
	{
		if (out.size() < 1)
		{
			throw std::out_of_range("Target output buffer must have space for at least one byte");
		}
		out[0] = static_cast<std::byte>(size);
		cbUsed = 1;
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

bool DecodeSize(std::span<const std::byte> in, size_t &size, size_t &cbRead)
{
	uint32_t i = 0;

	size = 0;
	cbRead = 0;

	if (in.size() == 0)
	{
		return false;
	}

	// Detect short form
	if ((in[0] & std::byte{0x80}) == std::byte{0})
	{
		size = std::to_integer<size_t>(in[0]);
		cbRead = 1;
		return true;
	}

	auto bytesToDecode = std::to_integer<size_t>(in[0] & ~std::byte{0x80});
	uint64_t tmp = 0;

	// Decode a maximum of 8 bytes, which adds up to a 56-bit number
	// That's MUCH bigger than anything we could possibly decode
	// And bytes to decode has to be at least one, or it isn't legal
	// Note - the case of 1 happens when you have a length between 128 and 255,
	// so the high bit is set, which precludes short form, resulting in a pattern of 0x81, 0x8b
	// to encode the value of 139.
	if (bytesToDecode > 8 || bytesToDecode + 1 > in.size() || bytesToDecode == 0)
		return false;

	cbRead = bytesToDecode + 1;

	for (i = 1; i < cbRead; ++i)
	{
		tmp += std::to_integer<uint8_t>(in[i]);

		if (i < bytesToDecode)
			tmp <<= 8;
	}

	// We now have the size in a 64-bit value, check whether it fits in a size_t
	// Arbitrarily say that max size is 1/2 SIZE_T_MAX
	size_t maxSize = (~(static_cast<size_t>(0))) >> 1;

	if (tmp > maxSize)
	{
		return false;
	}

	size = static_cast<size_t>(tmp);
	return true;
}

/*
	Used only in debugging, doesn't need a wchar_t output
*/
class BasicDerType
{
public:
	BasicDerType(std::span<const std::byte> in) : type(in)
	{
		if (in.size() < 2)
			throw std::exception(); // "Type too small"
	}

	BasicDerType() = delete;

	friend std::ostream &operator<<(std::ostream &os, const BasicDerType &type)
	{
		DerTypeContainer typeContainer(type.type[0]);

		if (typeContainer._class != DerClass::Universal || typeContainer.constructed)
		{
			os << "Unsupported type";
			return os;
		}

		size_t cbUsed = 0;

#pragma warning(disable : 4061)
		switch (typeContainer.type)
		{
		case DerType::External:
		case DerType::Real:
		case DerType::EmbeddedPDV:
		case DerType::RelativeOid:
		case DerType::Reserved1:
		case DerType::Reserved2:
		case DerType::Sequence:
		case DerType::Set:
		case DerType::CharacterString:
		case DerType::GraphicString:
		case DerType::NumericString:
		case DerType::ObjectDescriptor:
		case DerType::VideotexString:
		case DerType::UniversalString:
		default:
			os << "Unsupported type";
			break;

		case DerType::EOC:
			os << ""; // Has no data
			break;

		case DerType::Boolean:
		{
			Boolean x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::Integer:
		{
			Integer x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::BitString:
		{
			BitString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::OctetString:
		{
			OctetString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::Null:
		{
			Null x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::ObjectIdentifier:
		{
			ObjectIdentifier x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::Enumerated:
		{
			Enumerated x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::UTF8String:
		{
			UTF8String x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::PrintableString:
		{
			PrintableString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::T61String:
		{
			T61String x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::IA5String:
		{
			IA5String x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::UTCTime:
		{
			UTCTime x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::GeneralizedTime:
		{
			GeneralizedTime x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::VisibleString:
		{
			VisibleString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::GeneralString:
		{
			GeneralString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;

		case DerType::BMPString:
		{
			BMPString x;
			if (!x.Decode(type.type, cbUsed))
				throw std::exception(); // Decode error
			os << x;
		}
		break;
		}
#pragma warning(default : 4061)

		return os;
	}

	std::span<const std::byte> type;
};

void DebugDer(std::ostream &outFile, std::span<const std::byte> in, uint32_t level)
{
	if (in.size() < 2)
		throw std::exception(); // Corrupt input

	size_t size = 0;
	size_t cbRead = 0;
	size_t offset = 0;

	while (offset < in.size())
	{
		DerTypeContainer type(in[offset]);
		offset += 1;
		auto innerSpan = in.subspan(offset);
		if (!DecodeSize(innerSpan, size, cbRead))
			throw std::exception(); // Corrupt input

		offset += cbRead;

		outFile << std::setfill(' ') << std::setw(level + 1) << "  ";

		if (type.constructed)
		{
			// It is a set, or sequence, possibly app-specific
			// Print just the type, and the size, then recurse
			outFile << type << " 0x" << std::setfill('0') << std::setw(2) << std::hex << size << std::endl;
			DebugDer(outFile, innerSpan, level + 1);
		}
		else
		{
			// It is a primitive type
			outFile << type << " 0x" << std::setfill('0') << std::setw(2) << std::hex << size << " " << BasicDerType(in) << std::endl;
		}

		// And increment to the next item
		offset += static_cast<size_t>(size);
	}
}
