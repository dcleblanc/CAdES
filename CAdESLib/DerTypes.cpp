// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "Common.h"

std::ostream &operator<<(std::ostream &os, const DerTypeContainer &type)
{
	switch (type._class)
	{
	case DerClass::Universal:
		break;
	case DerClass::Application:
		os << "Application ";
		break;
	case DerClass::ContextSpecific:
		os << "Context-specific ";
		break;
	case DerClass::Private:
		os << "Private ";
		break;
	}

	if (type.constructed)
		os << "Constructed ";

	if (type._class != DerClass::Universal)
	{
		os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)static_cast<std::byte>(type.type);
		os << std::setfill(' ');
		return os;
	}

#pragma warning(disable : 4061)
	switch (type.type)
	{
	case DerType::EOC:
		os << "EOC";
		break;

	case DerType::Boolean:
		os << "Boolean";
		break;

	case DerType::Integer:
		os << "Integer";
		break;

	case DerType::BitString:
		os << "BitString";
		break;

	case DerType::OctetString:
		os << "OctetString";
		break;

	case DerType::Null:
		os << "Null";
		break;

	case DerType::ObjectIdentifier:
		os << "ObjectIdentifier";
		break;

	case DerType::ObjectDescriptor:
		os << "ObjectDescriptor";
		break;

	case DerType::External:
		os << "External";
		break;

	case DerType::Real:
		os << "Real";
		break;

	case DerType::Enumerated:
		os << "Enumerated";
		break;

	case DerType::EmbeddedPDV:
		os << "EmbeddedPDV";
		break;

	case DerType::UTF8String:
		os << "UTF8String";
		break;

	case DerType::RelativeOid:
		os << "RelativeOid";
		break;

	case DerType::Reserved1:
		os << "Reserved1(14)";
		break;

	case DerType::Reserved2:
		os << "Reserved2(15)";
		break;

	case DerType::Sequence:
		os << "Sequence";
		break;

	case DerType::Set:
		os << "Set";
		break;

	case DerType::NumericString:
		os << "NumericString";
		break;

	case DerType::PrintableString:
		os << "PrintableString";
		break;

	case DerType::T61String:
		os << "T61String";
		break;

	case DerType::VideotexString:
		os << "VideotexString";
		break;

	case DerType::IA5String:
		os << "IA5String";
		break;

	case DerType::UTCTime:
		os << "UTCTime";
		break;

	case DerType::GeneralizedTime:
		os << "GeneralizedTime";
		break;

	case DerType::GraphicString:
		os << "GraphicString";
		break;

	case DerType::VisibleString:
		os << "VisibleString";
		break;

	case DerType::GeneralString:
		os << "GeneralString";
		break;

	case DerType::UniversalString:
		os << "UniversalString";
		break;

	case DerType::CharacterString:
		os << "CharacterString";
		break;

	case DerType::BMPString:
		os << "BMPString";
		break;

	default:
		os << "Unknown type " << static_cast<uint8_t>(type.type);
		break;
	}
#pragma warning(default : 4061)

	return os;
}

void BitString::SetValue(uint8_t unusedBits, const std::byte *data, size_t cb)
{
	// First byte specifies how many trailing bits aren't used
	if (unusedBits > 7)
		throw std::invalid_argument("Too many unused bits");

	value.clear();
	value.resize(cb + 1);
	value[0] = std::byte{unusedBits};
	value.insert(value.begin() + 1, data, data + cb);
}

bool ObjectIdentifier::ToString(std::string &out) const
{
	// If possible, just look it up in our table
	const char *szOid = this->GetOidString();

	if (szOid != nullptr)
		out = szOid;

	std::string tmp;
	// size_t cbRead = 0;
	// size_t pos = 0;
	// uint32_t node = 0;

	// if (value.size() < 1)
	// 	return false;

	// auto valueNum = std::to_integer<uint32_t>(value[0]);
	// if (valueNum < 40)
	// {
	// 	tmp = "0";
	// 	tmp += "." + std::to_string(valueNum);
	// 	cbRead = 1;
	// }
	// else if (valueNum < 80)
	// {
	// 	tmp = "1";
	// 	tmp += "." + std::to_string(valueNum - 40);
	// 	cbRead = 1;
	// }
	// else
	// {
	// 	if (!DecodeLong(&valueNum, value.size(), node, cbRead) || node < 80)
	// 		return false;

	// 	tmp = "2";
	// 	tmp += "." + std::to_string(node - 80);
	// }

	// pos = cbRead;

	// for (; pos < value.size(); pos += cbRead)
	// {
	// 	if (!DecodeLong(&value[pos], value.size(), node, cbRead))
	// 		return false;

	// 	tmp += "." + std::to_string(node);
	// }

	out.swap(tmp);
	return true;
}

bool ObjectIdentifier::ToString(std::wstring &out) const
{
	// If possible, just look it up in our table
	const char *szOid = this->GetOidString();

	if (szOid != nullptr)
		out = utf8ToUtf16(szOid);

	std::wstring tmp;
	// size_t cbRead = 0;
	// size_t pos = 0;
	// uint32_t node = 0;

	// if (value.size() < 1)
	// 	return false;

	// if (value[0] < 40)
	// {
	// 	tmp = L"0";
	// 	tmp += L"." + std::to_wstring(value[0]);
	// 	cbRead = 1;
	// }
	// else if (value[0] < 80)
	// {
	// 	tmp = L"1";
	// 	tmp += L"." + std::to_wstring(value[0] - 40);
	// 	cbRead = 1;
	// }
	// else
	// {
	// 	if (!DecodeLong(&value[0], value.size(), node, cbRead) || node < 80)
	// 		return false;

	// 	tmp = L"2";
	// 	tmp += L"." + std::to_wstring(node - 80);
	// }

	// pos = cbRead;

	// for (; pos < value.size(); pos += cbRead)
	// {
	// 	if (!DecodeLong(&value[pos], value.size(), node, cbRead))
	// 		return false;

	// 	tmp += L"." + std::to_wstring(node);
	// }

	out.swap(tmp);
	return true;
}

void ObjectIdentifier::SetValue(const char *szOid)
{
	/*
	Current encoding practice is to multiply the first number by 40, then add the second.
	Practically, anything we care about with respect to crypto starts with 1.

	But let's try to make a general purpose library where we can, so there are the following:
	0, followed by 0-5 as possible values
	1, followed by 0-3
	2, followed by 0-51, with 999 used as an example

	We can then tell which of the three cases we have like so:
	0 - the value is < 40
	1 - value is < 80 and >= 40
	2 - value is >= 80

	*/
	value.clear();

	// This is going to require a substantial parser
	const char *tmp = szOid;
	uint32_t first, second;
	const char *next = nullptr;
	std::byte buf[8];
	size_t cbUsed = 0;

	// The first two are special
	GetNextLong(tmp, next, first);

	if (next == nullptr || first > 2)
		throw std::invalid_argument("Illegal OID");

	tmp = next;
	GetNextLong(tmp, next, second);

	EncodeLong(first * 40 + second, buf, sizeof(buf), cbUsed);

	value.insert(value.begin(), buf, buf + cbUsed);

	// Now keep going to get the rest of the OID
	while (next != nullptr)
	{
		tmp = next;
		GetNextLong(tmp, next, first);
		EncodeLong(first, buf, sizeof(buf), cbUsed);
		value.insert(value.end(), buf, buf + cbUsed);
	}

	SetOidIndex();
}

void ObjectIdentifier::EncodeLong(uint32_t in, std::byte *out, size_t cbOut, size_t &cbUsed)
{
	// Need to encode the bytes to base 128
	// any byte after the first needs to have high bit set
	// Short circuit small values
	if (in < 0x80)
	{
		if (cbOut < 1)
			throw std::invalid_argument("Output buffer too small");

		cbUsed = 1;
		out[0] = static_cast<std::byte>(in);
		return;
	}

	std::byte buf[8];
	// We know we need the last byte
	buf[7] = static_cast<std::byte>(in & 0x7f);
	in >>= 7;
	cbUsed = 1;

	int32_t i;

	for (i = sizeof(buf) - 2; i >= 0; --i)
	{
		buf[i] = static_cast<std::byte>((in & 0x7f) | 0x80);
		in >>= 7;
		cbUsed++;

		if (in == 0)
			break;
	}

	if (cbOut < cbUsed)
		throw std::invalid_argument("Output buffer too small");

	std::byte *data = buf + (sizeof(buf) - cbUsed);
	memcpy_s(out, cbOut, data, cbUsed);
	return;
}

bool ObjectIdentifier::DecodeLong(const std::span<std::byte> in, size_t cbIn, uint32_t &out, size_t &cbRead) const
{
	uint64_t tmp = 0;

	uint32_t i;
	for (i = 0; i < cbIn && i < 6; ++i)
	{
		// we can't possibly overflow a 64-bit value with only 42 bits of input
		tmp += std::to_integer<uint8_t>(std::byte{0x7f} & in[i]);

		if ((in[i] &  std::byte{0x80}) == std::byte{0})
			break;

		tmp <<= 7;
	}

	if (tmp >> 32 != 0 || i == 6)
	{
		// malformed input
		return false;
	}

	out = static_cast<uint32_t>(tmp);
	cbRead = i + 1;
	return true;
}

void ObjectIdentifier::GetNextLong(const char *start, const char *&next, uint32_t &out)
{
	char *end = nullptr;
	uint32_t tmp = strtoul(start, &end, 10);

	// If end is an invalid character, then fail
	switch (*end)
	{
	case '.':
	case '\0':
		break;
	default:
		throw std::invalid_argument("Illegal OID");
	}

	// 0 is a legal OID value
	// but it is how strtoul returns an error, which we can tell if end == start
	// for example if we had "1..2"
	if (tmp == 0 && start == end)
		throw std::invalid_argument("Illegal OID");

	out = tmp;
	next = *end == '\0' ? nullptr : end + 1;
}

bool PrintableString::SetValue(const char *str)
{
	const char *tmp = str;
	if (str == nullptr)
		return false;

	for (; *tmp != '\0'; ++tmp)
	{
		if (!isalnum(*tmp))
		{
			switch (*tmp)
			{
			case ' ':
			case '\'':
			case '(':
			case ')':
			case '+':
			case ',':
			case '-':
			case '.':
			case '/':
			case ':':
			case '=':
			case '?':
				break;
			default:
				return false;
			}
		}
	}

	value = str;
	return true;
}

namespace
{
	void EncodeVector(DerType type, const std::vector<std::byte> &in, std::byte *out, size_t cbOut, size_t &cbUsed)
	{
		// If it is empty, encode as Null
		if (in.size() == 0)
		{
			if (cbOut < 2)
				throw std::overflow_error("Overflow in EncodeVector");

			out[0] = static_cast<std::byte>(DerType::Null);
			out[1] = std::byte{0};
			cbUsed = 2;
			return;
		}

		size_t cbUsedSize = 0;
		size_t cbNeeded = in.size() + 1; // Data, plus tag
		uint64_t encodedSize;
		//std::byte encodedSize[sizeof(int64_t)];

		//EncodeSize(in.size(), &encodedSize, sizeof(encodedSize), cbUsedSize);

		// Note - cbUsedSize guaranteed to be <= 8, int32_t overflow not possible
		cbNeeded += cbUsedSize;

		if (cbNeeded > cbOut)
			throw std::length_error("Insufficient Buffer");

		out[0] = static_cast<std::byte>(type);
		size_t offset = 1;
		memcpy_s(out + offset, cbOut - offset, &encodedSize, cbUsedSize);
		offset += cbUsedSize;
		memcpy_s(out + offset, cbOut - offset, &in[0], in.size());

		cbUsed = offset + in.size();
		return;
	}

	template <typename T>
	std::vector<std::byte> EncodeString(DerType type, const std::basic_string<T> &in)
	{
		// If it is empty, encode as Null
		if (in.size() == 0)
		{
			if (cbOut < 2)
				throw std::overflow_error("Overflow in EncodeString");

			out[0] = static_cast<std::byte>(DerType::Null);
			out[1] = std::byte{0};
			cbUsed = 2;
			return;
		}

		const size_t charSize = sizeof(T);
		size_t cbUsedSize = 0;
		size_t cbNeeded = (in.size() + 1) * charSize; // Data, plus tag
		std::byte encodedSize[sizeof(int64_t)];

		EncodeSize(in.size() * charSize, encodedSize, sizeof(encodedSize), cbUsedSize);

		// Note - cbUsedSize guaranteed to be <= 8, int32_t overflow not possible
		cbNeeded += cbUsedSize;

		if (cbNeeded > cbOut)
			throw std::length_error("Insufficient Buffer");

		out[0] = static_cast<std::byte>(type);
		size_t offset = 1;
		memcpy_s(out + offset, cbOut - offset, encodedSize, cbUsedSize);
		offset += cbUsedSize;
		memcpy_s(out + offset, cbOut - offset, &in[0], in.size() * charSize);

		cbUsed = offset + in.size() * charSize;
		return;
	}
}

void Boolean::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	std::byte buf[3];

	buf[0] = static_cast<std::byte>(DerType::Boolean);
	buf[1] = std::byte{1};
	buf[2] = b != std::byte{0} ? std::byte{0xff} : std::byte{0};

	if (cbOut >= 3)
	{
		memcpy_s(pOut, cbOut, buf, sizeof(buf));
		cbUsed = 3;
		return;
	}

	throw std::exception(); // Encode Buffer Overrun
}

bool Boolean::Decode(const std::byte *pIn, size_t cbIn, size_t &cbUsed)
{
	size_t size = 0;
	size_t cbPrefix = 0;
	if (!CheckDecode(pIn, cbIn, DerType::Boolean, size, cbPrefix))
	{
		return DecodeNull(pIn, cbIn, cbUsed);
	}

	// Now check specifics for this type
	if (cbPrefix + size != 3)
		throw std::exception(); // Incorrect decode

	b = pIn[2] != std::byte{0} ? std::byte{0xff} : std::byte{0};
	cbUsed = 3;
	return true;
}

void Integer::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeVector(DerType::Integer, value, pOut, cbOut, cbUsed);
	
}

void BitString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeVector(DerType::BitString, value, pOut, cbOut, cbUsed);
	
}

void OctetString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeVector(DerType::OctetString, value, pOut, cbOut, cbUsed);
	
}

void Enumerated::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	if (cbOut < 3)
		throw std::overflow_error("Overflow in Enumerated::Encode");

	pOut[0] = static_cast<std::byte>(DerType::Enumerated);
	pOut[1] = std::byte{1};
	pOut[2] = value;
	cbUsed = 3;
	
}

void ObjectIdentifier::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeVector(DerType::ObjectIdentifier, value, pOut, cbOut, cbUsed);
	
}

void UTCTime::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	pOut = EncodeString<char>(DerType::UTCTime, value);
}

void GeneralizedTime::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::GeneralizedTime, value, pOut, cbOut, cbUsed);
	
}

void Time::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	if (cbOut < 2)
		throw std::overflow_error("Overflow in EncodeString");

	if (type == TimeType::GeneralizedTime)
		EncodeString<char>(DerType::GeneralizedTime, value, pOut, cbOut, cbUsed);
	else if (type == TimeType::UTCTime)
		EncodeString<char>(DerType::UTCTime, value, pOut, cbOut, cbUsed);
	else
	{
		pOut[0] = static_cast<std::byte>(DerType::Null);
		pOut[1] = std::byte{0};
	}
	
}

bool Time::Decode(const std::byte *pIn, size_t cbIn, size_t &cbUsed)
{
	// Sort out which of the two we have
	if (cbIn < 2)
		return false;

	DerType dertype = static_cast<DerType>(pIn[0]);
	bool fRet = false;

#pragma warning(disable : 4061)
	switch (dertype)
	{
	case DerType::GeneralizedTime:
	case DerType::UTCTime:
		fRet = DerBase::Decode(pIn, cbIn, dertype, cbUsed, value);
		break;

	case DerType::Null:
		if (pIn[1] == std::byte{0})
		{
			cbUsed = 2;
			type = TimeType::NotSet;
			return true;
		}
		break;

	default:
		break;
	}
#pragma warning(default : 4061)

	if (!fRet)
	{
		cbUsed = 0;
		type = TimeType::NotSet;
		return fRet;
	}

	type = dertype == DerType::GeneralizedTime ? TimeType::GeneralizedTime : TimeType::UTCTime;
	return fRet;
}

bool Time::ToString(std::string &out) const
{
	// Print this out as YYYY/MM/DD HH:MM:SSZ
	size_t offset = 0;
	switch (type)
	{
	case TimeType::GeneralizedTime:
		out.append(value, offset, 4);
		offset = 4;
		break;

	case TimeType::UTCTime:
		if (value[0] < '5')
		{
			out = "20";
		}
		else
		{
			out = "19";
		}

		out.append(value, offset, 2);
		offset = 2;
		break;
	case TimeType::NotSet:
		return false;
	}

	out += '/';
	// MM
	out.append(value, offset, 2);
	offset += 2;
	out += '/';
	// DD
	out.append(value, offset, 2);
	offset += 2;

	out += ' ';
	// HH
	out.append(value, offset, 2);
	offset += 2;
	out += ':';
	// MM
	out.append(value, offset, 2);
	offset += 2;
	out += ':';
	// SS
	out.append(value, offset, 3);
	return true;
}

void IA5String::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::IA5String, value, pOut, cbOut, cbUsed);
	
}

void GeneralString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::GeneralString, value, pOut, cbOut, cbUsed);
	
}

void PrintableString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::PrintableString, value, pOut, cbOut, cbUsed);
	
}

void T61String::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::T61String, value, pOut, cbOut, cbUsed);
	
}

void UTF8String::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::UTF8String, value, pOut, cbOut, cbUsed);
	
}

void VisibleString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char>(DerType::VisibleString, value, pOut, cbOut, cbUsed);
	
}

void UniversalString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<char32_t>(DerType::UniversalString, value, pOut, cbOut, cbUsed);
	
}

void BMPString::Encode(std::byte *pOut, size_t cbOut, size_t &cbUsed)
{
	EncodeString<wchar_t>(DerType::BMPString, value, pOut, cbOut, cbUsed);
	
}

// Shouldn't need this for this class, but everything needs it implemented

size_t AnyType::SetDataSize()
{
	if (encodedValue.size() <= 2)
		cbData = 0;

	size_t tmp = 0;
	size_t cbRead = 0;

	if (!::DecodeSize(&encodedValue[1], encodedValue.size() - 1, tmp, cbRead))
		throw std::exception(); // Error in DecodeSize

	cbData = static_cast<size_t>(tmp);
	return cbData;
}

bool AnyType::ToString(std::string &out) const
{
	out.clear();

#pragma warning(disable : 4061)
	switch (GetDerType())
	{
	case DerType::Null:
		out = "";
		break;

	case DerType::IA5String:
	case DerType::GeneralString:
	case DerType::PrintableString:
	case DerType::T61String:
	case DerType::UTF8String:
	case DerType::VisibleString:
	{
		size_t valueSize = 0;
		size_t cbRead = 0;
		if (DecodeSize(&encodedValue[1], encodedValue.size() - 1, valueSize, cbRead))
		{
			const char *sz = reinterpret_cast<const char *>(&encodedValue[1 + cbRead]);
			out.reserve(valueSize);
			out.append(sz, valueSize);
			return true;
		}
		return false;
	}

	default:
		return false;
	}
#pragma warning(default : 4061)

	return false;
}

bool AnyType::ToString(std::wstring &out) const
{
	out.clear();

#pragma warning(disable : 4061)
	switch (GetDerType())
	{
	case DerType::Null:
		out = L"";
		break;

	case DerType::IA5String:
	case DerType::GeneralString:
	case DerType::PrintableString:
	case DerType::T61String:
	case DerType::UTF8String:
	case DerType::VisibleString:
	{
		size_t valueSize = 0;
		size_t cbRead = 0;
		if (DecodeSize(&encodedValue[1], encodedValue.size() - 1, valueSize, cbRead))
		{
			// This could be a non-null terminated character string
			const char *sz = reinterpret_cast<const char *>(&encodedValue[1 + cbRead]);
			std::string s;
			s.append(sz, valueSize);

			out = utf8ToUtf16(s);
			return true;
		}
		return false;
	}

	default:
		return false;
	}
#pragma warning(default : 4061)

	return false;
}

std::ostream &AnyType::Output(std::ostream &os, const AnyType &o)
{
	DerType type = o.GetDerType();
	bool fConverted = true;

#pragma warning(disable : 4061)
	switch (type)
	{
	case DerType::Boolean:
		fConverted = o.OutputFromType<Boolean>(os);
		break;

	case DerType::Integer:
		fConverted = o.OutputFromType<Integer>(os);
		break;

	case DerType::BitString:
		fConverted = o.OutputFromType<BitString>(os);
		break;

	case DerType::OctetString:
		fConverted = o.OutputFromType<OctetString>(os);
		break;

	case DerType::Null:
		os << "null";
		fConverted = true;
		break;

	case DerType::ObjectIdentifier:
		fConverted = o.OutputFromType<ObjectIdentifier>(os);
		break;

	case DerType::UTF8String:
		fConverted = o.OutputFromType<UTF8String>(os);
		break;

	case DerType::PrintableString:
		fConverted = o.OutputFromType<PrintableString>(os);
		break;

	case DerType::T61String: // aka TeletexString
		fConverted = o.OutputFromType<T61String>(os);
		break;

	case DerType::IA5String:
		fConverted = o.OutputFromType<IA5String>(os);
		break;

	case DerType::VisibleString:
		fConverted = o.OutputFromType<VisibleString>(os);
		break;

	case DerType::GeneralString:
		fConverted = o.OutputFromType<GeneralString>(os);
		break;

	case DerType::BMPString:
		fConverted = o.OutputFromType<BMPString>(os);
		break;

	case DerType::ObjectDescriptor:
	case DerType::External:
	case DerType::Real:
	case DerType::Enumerated:
	case DerType::EmbeddedPDV:
	case DerType::RelativeOid:
	case DerType::Reserved1:
	case DerType::Reserved2:
	case DerType::NumericString:
	case DerType::GraphicString:
	case DerType::CharacterString:
	case DerType::UniversalString:
	default:
		fConverted = false;
		break;
	}
#pragma warning(default : 4061)

	if (!fConverted)
	{
		for (size_t pos = 0; pos < o.encodedValue.size(); ++pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.encodedValue[pos];
		}
	}

	return os;
}

std::wostream &AnyType::Output(std::wostream &os, const AnyType &o)
{
	DerType type = o.GetDerType();
	bool fConverted = true;

#pragma warning(disable : 4061)
	switch (type)
	{
	case DerType::Boolean:
		fConverted = o.OutputFromType<Boolean>(os);
		break;

	case DerType::Integer:
		fConverted = o.OutputFromType<Integer>(os);
		break;

	case DerType::BitString:
		fConverted = o.OutputFromType<BitString>(os);
		break;

	case DerType::OctetString:
		fConverted = o.OutputFromType<OctetString>(os);
		break;

	case DerType::Null:
		os << L"null";
		fConverted = true;
		break;

	case DerType::ObjectIdentifier:
		fConverted = o.OutputFromType<ObjectIdentifier>(os);
		break;

	case DerType::UTF8String:
		fConverted = o.OutputFromType<UTF8String>(os);
		break;

	case DerType::PrintableString:
		fConverted = o.OutputFromType<PrintableString>(os);
		break;

	case DerType::T61String: // aka TeletexString
		fConverted = o.OutputFromType<T61String>(os);
		break;

	case DerType::IA5String:
		fConverted = o.OutputFromType<IA5String>(os);
		break;

	case DerType::VisibleString:
		fConverted = o.OutputFromType<VisibleString>(os);
		break;

	case DerType::GeneralString:
		fConverted = o.OutputFromType<GeneralString>(os);
		break;

	case DerType::BMPString:
		fConverted = o.OutputFromType<BMPString>(os);
		break;

	case DerType::ObjectDescriptor:
	case DerType::External:
	case DerType::Real:
	case DerType::Enumerated:
	case DerType::EmbeddedPDV:
	case DerType::RelativeOid:
	case DerType::Reserved1:
	case DerType::Reserved2:
	case DerType::NumericString:
	case DerType::GraphicString:
	case DerType::CharacterString:
	case DerType::UniversalString:
	default:
		fConverted = false;
		break;
	}
#pragma warning(default : 4061)

	if (!fConverted)
	{
		for (auto byteValue: o.encodedValue)
		{
			os << std::setfill(L'0') << std::setw(2) << std::hex << (uint8_t)byteValue;
		}
	}

	return os;
}
