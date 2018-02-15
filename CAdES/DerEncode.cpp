// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"
#include "CAdES.h"
#include "DerEncode.h"

bool EncodeSize(size_t size, unsigned char * out, size_t cbOut, size_t & cbUsed)
{
	unsigned char tmp[sizeof(unsigned long long)] = { 0 };
	unsigned int i = 0;

	if (size <= 0x7f && cbOut >= 1)
	{
		*out = static_cast<unsigned char>(size);
		cbUsed = 1;
		return true;
	}

	// Else the first byte is the number of following big-endian
	// non-zero bytes
	for (; i < sizeof(unsigned long long) - 1; ++i)
	{
		// Convert incoming size to big-endian order
		size_t offset = sizeof(unsigned long long) - (i + 1);
		tmp[offset] = static_cast<unsigned char>(size);
		size >>= 8;

		if (size == 0)
		{
			cbUsed = i + 1;
			tmp[offset - 1] = static_cast<unsigned char>(0x80 | (cbUsed));
			cbUsed++;
			break;
		}
	}

	// Detect abnormal loop exit
	if (size != 0)
		return false;

	if (cbOut >= cbUsed)
	{
		memcpy_s(out, cbOut, tmp + sizeof(long long) - cbUsed, cbUsed);
		return true;
	}
	
	return false;
}

bool DecodeSize(const unsigned char* in, size_t cbIn, size_t& size, size_t& cbRead)
{
	unsigned int i = 0;

	size = 0;
	cbRead = 0;

	if (cbIn == 0)
	{
		return false;
	}

	// Detect short form
	if ((in[0] & 0x80) == 0)
	{
		size = in[0];
		cbRead = 1;
		return true;
	}

	unsigned int bytesToDecode = static_cast<unsigned char>(in[0] & (~0x80));
	unsigned long long tmp = 0;

	// Decode a maximum of 8 bytes, which adds up to a 56-bit number
	// That's MUCH bigger than anything we could possibly decode
	// And bytes to decode has to be at least two, or it isn't legal DER
	if (bytesToDecode > 8 || bytesToDecode + 1 > cbIn || bytesToDecode < 2)
		return false;

	cbRead = bytesToDecode + 1;

	for (i = 1; i < cbRead; ++i)
	{
		tmp += in[i];

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

class BasicDerType
{
public:
	BasicDerType(const unsigned char * pIn, size_t cbIn) : pType(pIn), cb(cbIn) 
	{
		if (cb < 2)
			throw std::exception("Type too small");
	}

	BasicDerType() = delete;

	friend std::ostream& operator<<(std::ostream& os, const BasicDerType& type)
	{
		DerTypeContainer typeContainer(type.pType[0]);

		if (typeContainer._class != DerClass::Universal || typeContainer.constructed)
		{
			os << "Unsupported type";
			return os;
		}

		size_t cbUsed = 0;

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
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
			break;

		case DerType::Integer:
		{
			Integer x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
			break;

		case DerType::BitString:
		{
			BitString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::OctetString:
		{
			OctetString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::Null:
		{
			Null x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::ObjectIdentifier:
		{
			ObjectIdentifier x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::Enumerated:
		{
			Enumerated x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::UTF8String:
		{
			UTF8String x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::PrintableString:
		{
			PrintableString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::T61String:
		{
			T61String x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::IA5String:
		{
			IA5String x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::UTCTime:
		{
			UTCTime x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::GeneralizedTime:
		{
			GeneralizedTime x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::VisibleString:
		{
			VisibleString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::GeneralString:
		{
			GeneralString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		case DerType::BMPString:
		{
			BMPString x;
			if (!x.Decode(type.pType, type.cb, cbUsed))
				throw std::exception("Decode error");
			os << x;
		}
		break;

		}

		return os;
	}

	const unsigned char* pType;
	size_t cb;
};

void DebugDer(const unsigned char * pIn, size_t cbIn, unsigned long level)
{
	if (cbIn < 2)
		throw std::exception("Corrupt input");

	size_t size = 0;
	size_t cbRead = 0;
	size_t offset = 0;

	while (offset < cbIn)
	{
		DerTypeContainer type(*(pIn + offset));
		const unsigned char* pType = pIn + offset;
		size_t cbType = cbIn - offset;

		offset += 1;
		if (!DecodeSize(pIn + offset, cbIn - offset, size, cbRead))
			throw std::exception("Corrupt input");

		offset += cbRead;

		std::cout << std::setfill(' ') << std::setw(level + 1) << "  ";

		if (type.constructed)
		{
			// It is a set, or sequence, possibly app-specific
			// Print just the type, and the size, then recurse
			std::cout << type << " 0x" << std::setfill('0') << std::setw(2) << std::hex << size << std::endl;
			DebugDer(pIn + offset, size, level + 1);
		}
		else
		{
			// It is a primitive type
			std::cout << type << " 0x" << std::setfill('0') << std::setw(2) << std::hex << size << " " << BasicDerType(pType, cbType) << std::endl;
		}

		// And increment to the next item
		offset += static_cast<size_t>(size);

	}

}
