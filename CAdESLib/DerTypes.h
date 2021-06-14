// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

/* Start basic DER encoding types */

/*
	This is actually a bitfield, roughly defined as
	struct DerType
	{
		std::byte class : 2,
		std::byte constructed : 1, // Constructed = 1, Primitive = 0
		std::byte tag : 5
	}

	class is defined as follows:
	enum class DerClass
	{
		Universal = 0,
		Application = 1,
		ContextSpecific = 2,
		Private = 3
	};
*/

#include "Common.h"

#include "Oids.h"
#include "DerDecode.h"
#include "DerEncode.h"
#include <type_traits>

class DerTypeContainer
{
public:
	DerTypeContainer(std::byte c)
		: type(static_cast<DerType>(c & std::byte{0x1f})),
		  _class(static_cast<DerClass>((c & std::byte{0xc0}) >> 6)),
		  constructed(std::byte{0x20} == (c & std::byte{0x20}))
	{
	}

	operator std::byte()
	{
		return (static_cast<std::byte>(_class) << 6) | (constructed ? std::byte{0x20} : std::byte{0}) | (static_cast<std::byte>(type));
	}

	friend std::ostream &operator<<(std::ostream &os, const DerTypeContainer &type);

	DerType type;
	DerClass _class;
	bool constructed;
};

inline size_t GetSizeBytes(uint64_t size)
{
	if (size < 0x80)
		return 1;

	// After this, the first byte will be the count of bytes for the size
	if (size <= 0xff)
		return 2;

	if (size <= 0xffff)
		return 3;

	if (size <= 0xffffff)
		return 4;

	if (size <= 0xffffffff)
		return 5;

	if (size <= 0xffffffffff)
		return 6;

	// 72,000 terabytes ought to be enough
	if (size <= 0xffffffffffff)
		return 7;

	return ~static_cast<size_t>(0);
}

// Create an interface to ensure consistency

class AnyType;

// Note - at least some classes need a way to determine if an AnyType class holds that class
namespace
{
	template <class T, class U>
	concept ConstructibleDerivedType = std::is_default_constructible<T>::value && std::is_base_of<U, T>::value;
}
class DerBase
{
public:
	DerBase() {}
	virtual ~DerBase() = default;

	virtual size_t EncodedSize() const
	{
		// No longer calling SetDataSize here
		// If the object is already fully loaded, then we know cbData, and don't need to
		// take the perf hit of recalculating it.
		// If it has been set some other way, say we're building the object
		// directly, then call SetDataSize when you're done.
		return 1 + GetSizeBytes(cbData) + cbData;
	}

	virtual void Encode(std::span<std::byte> out) = 0;
	virtual bool Decode(DerDecode decoder) = 0;


	size_t Size() const { return cbData; }

protected:
	virtual size_t SetDataSize() = 0;

	// Don't calculate the data size more than once
	size_t cbData;
};

/*
    There are two incarnations of optional items,
    EXPLICIT and IMPLICIT

    In the case of EXPLICIT, there will be the tag specifying which option it is, followed by a size,
    then the actual contained type. If it is IMPLICIT, it won't be contained, but will behave as if we just substituted
    the tag of the type it contains for the initial optional tag.

    Note - there are some implicit types seen in a CHOICE that are tagged as 0x80, 0x81, etc. But for something that is just 
    OPTIONAL, it might be the actual type, and the structure just terminates on a prior member if it isn't present.
*/

enum class OptionType
{
	Implicit = 0,
	Explicit,
};

template <typename T, std::byte type, OptionType optionType>
class ContextSpecificHolder;

template <typename T, std::byte type>
class ContextSpecificHolder<T, type, OptionType::Explicit>
{
public:
	ContextSpecificHolder() : hasData(false) {}

	size_t EncodedSize() const
	{
		size_t innerSize = innerType.EncodedSize();

		// if innerType decodes to null, then this isn't present
		// Mirror the logic in Encode
		if (innerSize <= 2)
			return 0;

		return 1 + GetSizeBytes(innerSize) + innerSize;
	}

	// This contains an encapsulated type, and it has a type
	// that is defined by the context
	bool Decode(DerDecode decoder)
	{
		return decoder.Decode<T, type>(innerType, hasData);
	}

	void Encode(std::span<std::byte> out)
	{
		// Handle the case where there is no data, and we shouldn't write out anything
		size_t innerSize = innerType.EncodedSize();

		if (innerSize <= 2)
		{
			return;
		}

		size_t cbSize = GetSizeBytes(innerSize);

		if (1 + cbSize + innerSize > out.size())
		{
			throw std::out_of_range("Insufficient buffer");
		}

		size_t offset = 1;

		out[0] = type;
		EncodeHelper::EncodeSize(innerSize, out.subspan(offset));

		innerType.Encode(out.subspan(offset));
	}

	const T &GetInnerType() const { return innerType; }
	bool HasData() const { return hasData; }

private:
	T innerType;
	bool hasData;
};

template <typename T, std::byte type>
class ContextSpecificHolder<T, type, OptionType::Implicit>
{
public:
	ContextSpecificHolder() : hasData(false) {}

	size_t EncodedSize()
	{
		if (innerType.Size() == 0)
			return 0;

		return innerType.EncodedSize();
	}

	bool IsPresent(std::byte t) const { return t == type; }

	bool Decode(DerDecode decoder)
	{
		// If this is an optional type, we could have used
		// all the bytes on the previous item
		if (decoder.RemainingData().size() == 0)
			throw std::out_of_range("Insufficient buffer");

		if (IsPresent(decoder.RemainingData()[0]))
		{
			return innerType.Decode(decoder);
		}

		return false;
	}

	void Encode(std::span<std::byte> out)
	{
		// Handle the case where there is no data, and we shouldn't write out anything
		size_t innerSize = innerType.EncodedSize();

		if (innerSize <= 2)
		{
			return;
		}

		size_t cbSize = GetSizeBytes(innerSize);

		if (1 + cbSize + innerSize > out.size())
		{
			throw std::out_of_range("Insufficient buffer");
		}

		out[0] = static_cast<std::byte>(type);
		// A non-constructed type is the same as the type it wraps,
		// except for the type byte, which will be ([0x80 or 0xA0] | option number)
		innerType.Encode(out);
	}

	const T &GetInnerType() const { return innerType; }
	T &GetInnerType() { return innerType; }

	bool HasData() const { return hasData; }

private:
	T innerType;
	bool hasData;
};

// In order for this to work without being overly clunky,
// this type will only hold encoded types
class AnyType final : public DerBase
{
public:
	// encode this to NULL if empty
	size_t EncodedSize() const override
	{
		return encodedValue.size();
	}

	void SetNull()
	{
		encodedValue.clear();
		encodedValue;
	}

	template <typename T>
	void SetValue(T &in)
	{
		size_t cbOut = in.EncodedSize();
		encodedValue.clear();
		encodedValue.resize(cbOut);

		in.Encode(encodedValue);
	}

	virtual void Encode(std::span<std::byte> out) override
	{
		// Should be encoded already
		if (encodedValue.size() == 0)
			SetNull();

		if (encodedValue.size() > out.size())
		{
			throw std::overflow_error("Not enough space to store encoded value");
		}
		std::copy(encodedValue.begin(), encodedValue.end(), out.begin());
	}

	virtual bool Decode(DerDecode decoder) override
	{
		auto remaining = decoder.RemainingData();
		// This can hold anything, by design. Just copy the bytes, might be a Null
		if (remaining.size() < 2)
			return false;

		if (remaining[0] == static_cast<std::byte>(DerType::Null))
		{
			if (remaining[1] == std::byte{0})
			{
				cbData = 2;
				return true;
			}
			return false;
		}
		else
		{
			size_t size = 0;
			size_t cbPrefix = 0;

			if (!DerDecode::DecodeSize(remaining.subspan(1), size, cbPrefix) || 1 + cbPrefix + size > remaining.size())
				throw std::out_of_range("Illegal size value");

			encodedValue.clear();
			encodedValue.resize(remaining.size());
			cbData = 1 + cbPrefix + static_cast<size_t>(size);
			std::copy(remaining.begin(), remaining.end(), encodedValue.begin());

			return true;
		}
	}

	const std::span<const std::byte> GetBuffer() const { return std::span{encodedValue}; }
	size_t GetBufferSize() const { return encodedValue.size(); }

	// Shouldn't need this for this class, but everything needs it implemented
	virtual size_t SetDataSize() override;

	static std::ostream &Output(std::ostream &os, const AnyType &o);
	template <typename CharType>
	friend std::basic_ostream<CharType> &operator<<(std::basic_ostream<CharType> &os, const AnyType &o)
	{
		return Output(os, o);
	}

	bool ToString(std::string &out) const;
	bool ToString(std::wstring &out) const;

	DerType GetDerType() const { return encodedValue.size() > 1 ? static_cast<DerType>(encodedValue[0]) : DerType::Null; }

	const AnyType &operator=(const AnyType &rhs)
	{
		encodedValue = rhs.encodedValue;
		return *this;
	}

	std::span<const std::byte> GetData() const { return encodedValue; }

	template <ConstructibleDerivedType<DerBase> T>
	bool ConvertToType(T &type) const
	{
		size_t decodedSize = 0;
		DerDecode decoder{std::span{encodedValue}, decodedSize};
		return type.Decode(decoder);
	}

	template <ConstructibleDerivedType<DerBase> T>
	bool OutputFromType(std::ostream &os) const
	{
		T t;
		bool fConverted = ConvertToType(t);
		if (fConverted)
			os << t;

		return fConverted;
	}

private:
	std::vector<std::byte> encodedValue;
	static constexpr std::vector<std::byte> nullBytes = { std::byte{(uint8_t)DerType::Null}, std::byte{0}};
};

/*
    Any class that derives from this will need an enum converting the type
    to what is defined for the class, and a set of accessors that return the desired data
    in the correct format.

    Note - it is possible to have a CHOICE that's constructed in any of the following ways:
    Foo ::= {
        [universal type],
        [universal type 2]
        }

    Foo ::= {
        [universal type],
        [context-specific ID]
        }

    Foo ::= {
        [context-specific ID]
        [context-specific ID2]
        }
 */

class ChoiceType : public DerBase
{
public:
	ChoiceType() : derType(std::byte{0xff}) {}

	virtual void Encode(std::span<std::byte> out) override
	{
		value.Encode(out);
	}

	virtual bool Decode(DerDecode decoder) override
	{
		if (value.Decode(decoder))
		{
			derType = decoder.InitialData()[0];
			cbData = 1;
			return true;
		}

		return false;
	}

	const AnyType &GetValue() const { return value; }

	// It appears that these are EXPLICIT, at least GeneralName is
	bool GetInnerType(AnyType &inner)
	{
		auto in = value.GetBuffer();
		DerDecode decoder{in, cbData};

		switch (decoder.InitSequenceOrSet())
		{
		case DecodeResult::Failed:
			return false;
		case DecodeResult::Null:
		case DecodeResult::EmptySequence:
			return true;
		case DecodeResult::Success:
			break;
		}

		return inner.Decode(decoder);
	}

	std::span<const std::byte> GetInnerBuffer(size_t &innerSize) const
	{
		auto in = value.GetBuffer();
		size_t cbPrefix = 0;

		innerSize = 0;

		if (!DerDecode::DecodeSize(in.subspan(1), innerSize, cbPrefix) || 1 + cbPrefix + innerSize > in.size())
			throw std::out_of_range("Illegal size value");

		return in.subspan(cbPrefix + 1);
	}

protected:
	virtual size_t SetDataSize() override { return value.SetDataSize(); }

	AnyType value;
	DerTypeContainer derType;
};

class Boolean final : public DerBase
{
public:
	Boolean(bool f = false)
	{
		if (f)
			b = std::byte{0xff};
		else
			b = std::byte{0};
	}

	void SetValue(bool f) { b = f ? std::byte{0xff} : std::byte{0}; }
	bool GetValue() const { return b == std::byte{0} ? false : true; }

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override;

	friend std::ostream &operator<<(std::ostream &os, const Boolean &b)
	{
		os << (b.b == std::byte{0} ? "false" : "true");
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const Boolean &b)
	{
		os << (b.b == std::byte{0} ? L"false" : L"true");
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = 1); }

	std::byte b;
};

// Allowed to be any size
class Integer final : public DerBase
{
public:
	template <typename T>
	void SetValue(T in)
	{
		static_assert(std::is_integral<T>::value, "Expected integer type");

		bool fAddLeadingZero = false;

		value.clear();

		// Short circuit the corner case where in == 0
		if (in == 0)
		{
			value.push_back(0);
			return;
		}

		if (std::is_unsigned<T>::value)
		{
			T testBit = in >> ((sizeof(T) * 8) - 1);

			if (testBit > 0)
				fAddLeadingZero = true;
		}

		value.resize(sizeof(T) + (fAddLeadingZero ? 1 : 0));

		if (fAddLeadingZero)
			value.push_back(0);

		std::byte *pData = reinterpret_cast<std::byte *>(&in);

		// Assuming that we're on a little-endian system, start at the end
		bool fHasData = false;

		for (int32_t i = sizeof(T) - 1; i >= 0; --i)
		{
			// Discard leading zeros
			if (!fHasData && pData[i] == 0)
				continue;

			fHasData = true;
			value.push_back(pData[i]);
		}
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::Integer,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const Integer &o)
	{
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const Integer &o)
	{
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill(L'0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		return os;
	}

	size_t ByteCount() const { return value.size(); }

	bool GetValue(uint32_t &data) const
	{
		auto cbValue = value.size();

		if (cbValue == 0)
			return false;

		// Test for leading zero
		if (value[0] == std::byte{0})
		{
			--cbValue;
		}

		if (cbValue > 4)
			return false;

		data = 0;
		for (size_t i = 0; i < cbValue; ++i)
		{
			data += std::to_integer<uint8_t>(value[i]);
			if (i < cbValue - 1)
				data <<= 8;
		}

		return true;
	}

	const std::span<const std::byte> &GetBytes() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<std::byte> value;
};

class BitString final : public DerBase
{
public:
	void SetValue(uint8_t unusedBits, std::span<const std::byte> data);

	virtual void Encode(std::span<std::byte> out) override;

	uint8_t UnusedBits() const { return value.size() > 0 ? std::to_integer<uint8_t>(value[0]) : (uint8_t)0; }

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::BitString,value);
	}

	size_t ValueSize() const
	{
		if (value.size() < 2)
			return 0;

		auto unusedBits = std::to_integer<uint8_t>(value[0]);
		return value.size() * 8 - unusedBits;
	}

	bool GetValue(uint8_t &unusedBits, std::vector<std::byte> &out) const
	{
		if (value.size() < 2)
			return false;

		unusedBits = std::to_integer<uint8_t>(value[0]);
		out.clear();
		out.resize(value.size() - 1);
		out.insert(out.begin(), value.begin() + 1, value.end());
		return true;
	}

	bool GetValue(std::span<const std::byte>& pValue)
	{
		if (value.size() < 2)
			return false;

		pValue = value;
		return true;
	}

	friend std::ostream &operator<<(std::ostream &os, const BitString &o)
	{
		const uint32_t linelength = 80;
		const std::byte *pData = &o.value[0];
		std::ostringstream osTmp;

		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			if (pos > 0 && (pos % linelength) == 0)
				osTmp << std::endl;

			// This is done byte by byte
			osTmp << std::setfill('0') << std::setw(2) << std::hex << std::to_integer<uint16_t>(pData[pos]);
		}

		os << osTmp.str();
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const BitString &o)
	{
		const uint32_t linelength = 80;
		const std::byte *pData = &o.value[0];
		std::wostringstream osTmp;

		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			if (pos > 0 && (pos % linelength) == 0)
				osTmp << std::endl;

			// This is done byte by byte
			osTmp << std::setfill(L'0') << std::setw(2) << std::hex << std::to_integer<uint16_t>(pData[pos]);
		}

		os << osTmp.str();
		return os;
	}

	const std::span<const std::byte> GetBits() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<std::byte> value;
};

class OctetString final : public DerBase
{
public:
	void SetValue(const std::vector<std::byte> &in)
	{
		value = in;
	}

	void SetValue(std::span<const std::byte> data)
	{
		value.clear();
		value.resize(data.size());
		value.insert(value.begin(), data.begin(), data.end());
	}

	// For use by extensions, which need to write
	// internal structs into the buffer.
	std::vector<std::byte> &Resize(size_t cb)
	{
		value.clear();
		value.resize(cb);
		return value;
	}

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::OctetString,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const OctetString &o)
	{
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		os << std::setfill(' ');
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const OctetString &o)
	{
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill(L'0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		os << std::setfill(L' ');
		return os;
	}

	const std::vector<std::byte> &GetValue() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<std::byte> value;
};

class Enumerated : public DerBase
{
public:
	Enumerated(std::byte v = std::byte{0xff}) : value(v) {}

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		size_t cbPrefix = 0;
		auto data = decoder.RemainingData();
		if (!decoder.CheckDecode(data ,DerType::Enumerated, cbPrefix))
		{
			cbData = 0;
			return false;
		}

		// Now check specifics for this type
		if (data.size() < 3 || cbPrefix != 1)
			throw std::length_error("Incorrect decode");

		value = data[2];
		cbData = 3;
		return true;
	}

	friend std::ostream &operator<<(std::ostream &os, const Enumerated &e)
	{
		os << std::to_integer<uint8_t>(e.value);
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const Enumerated &e)
	{
		os << std::to_integer<uint8_t>(e.value);
		return os;
	}

	std::byte GetValue() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = 1); }

	std::byte value;
};

class ObjectIdentifier final : public DerBase
{
public:
	ObjectIdentifier(std::string oid) : oidIndex(OidIndexUnknown)
	{
		SetValue(oid);
	}

	ObjectIdentifier() = default;

	static const size_t OidIndexUnknown = ~static_cast<size_t>(0);

	bool ToString(std::string &out) const;
	bool ToString(std::wstring &out) const;

	void SetValue(std::string oid);

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		bool fRet = decoder.Decode(DerType::ObjectIdentifier,value);

		if (fRet)
			SetOidIndex();

		return fRet;
	}

	template <typename CharType>
	friend std::basic_ostream<CharType> &operator<<(std::basic_ostream<CharType> &os, const ObjectIdentifier &obj)
	{
		std::basic_string<CharType> s;
		obj.ToString(s);

		os << s;
		return os;
	}

	std::string GetOidLabel() const
	{
		// This will internally ignore invalid values to return null
		return ::GetOidLabel(oidIndex);
	}

	std::string GetOidString() const
	{
		return ::GetOidString(oidIndex);
	}

	std::span<const std::byte> GetBytes() { return value; }

	bool IsEmpty() const { return value.size() == 0; }

	const ObjectIdentifier &operator=(const ObjectIdentifier &rhs)
	{
		value = rhs.value;
		oidIndex = rhs.oidIndex;
		return *this;
	}

	size_t GetOidIndex() const { return oidIndex; }

private:
	void SetOidIndex()
	{
		if (GetOidInfoIndex(value, oidIndex))
			return;

		oidIndex = ~static_cast<size_t>(0);
	}

	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	void EncodeLong(uint64_t in, std::span<std::byte> out);
	uint32_t DecodeLong(std::span<const std::byte> in, size_t &cbRead) const;
	uint32_t GetNextLong(const char *start, const char *&next);

	std::span<const std::byte> value;
	size_t oidIndex;
};

class UTCTime final : public DerBase
{
	friend class Time;

public:
	bool SetValue(time_t now)
	{
		tm gmt;
		gmtime_s(&gmt, &now);
		return SetValue(&gmt);
	}

	bool SetValue(tm *gmt)
	{
		if (gmt->tm_year >= 150)
			return false;

		// Ensure 2-digit year as per spec
		char tmp[16];
		sprintf_s(tmp, sizeof(tmp), "%02d%02d%02d%02d%02d%02dZ",
				  gmt->tm_year >= 100 ? gmt->tm_year - 100 : gmt->tm_year,
				  gmt->tm_mon + 1,
				  gmt->tm_mday,
				  gmt->tm_hour,
				  gmt->tm_min,
				  gmt->tm_sec);

		value = tmp;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::UTCTime,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const UTCTime &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const UTCTime &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class GeneralizedTime final : public DerBase
{
	friend class Time;
	// This has a 4 digit year, UTCTime has two digit year
	// Note - at least in the Microsoft CRT, this is actually 64-bit time
public:
	bool SetValue(time_t now)
	{
		tm gmt;
		gmtime_s(&gmt, &now);
		return SetValue(&gmt);
	}

	bool SetValue(tm *gmt)
	{
		// Ensure 4-digit year as per spec
		char tmp[16];
		sprintf_s(tmp, sizeof(tmp), "%04d%02d%02d%02d%02d%02dZ",
				  gmt->tm_year + 1900,
				  gmt->tm_mon + 1,
				  gmt->tm_mday,
				  gmt->tm_hour,
				  gmt->tm_min,
				  gmt->tm_sec);

		value = tmp;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::GeneralizedTime,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const GeneralizedTime &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const GeneralizedTime &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

/*
Note - Time ::= CHOICE {
utcTime        UTCTime,
generalTime    GeneralizedTime }

The RFC mandates an interesting behavior - for times in the form of YYMMDD[...]
then if YY >= 50, treat as 19YY, for years < 50, treat as 20YY. For dates outside that
range, then use Generalized time.
*/

enum class TimeType
{
	NotSet,
	UTCTime,
	GeneralizedTime
};

class Time final : public DerBase
{
public:
	Time() : type(TimeType::NotSet) {}

	bool SetValue()
	{
		time_t now;
		tm gmt;

		::time(&now);
		gmtime_s(&gmt, &now);

		if (gmt.tm_year < 50 || gmt.tm_year >= 150)
		{
			GeneralizedTime gt;
			gt.SetValue(&gmt);
			type = TimeType::GeneralizedTime;
			value.swap(gt.value);
		}
		else
		{
			UTCTime ut;
			ut.SetValue(&gmt);
			type = TimeType::UTCTime;
			value.swap(ut.value);
		}
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override;

	template <typename CharType>
	friend std::basic_ostream<CharType> &operator<<(std::basic_ostream<CharType> &os, const Time &str)
	{
		os << str.value.c_str();
		return os;
	}

	bool ToString(std::string &out) const;
	const std::string &GetValue() const { return value; }
	const std::wstring GetValueW() const { return utf8ToUtf16(value); }

	TimeType GetType() const { return type; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
	TimeType type;
};

/*
For documentation on string types, see:
https://www.obj-sys.com/asn1tutorial/node128.html
*/

inline bool IsAscii(std::string str)
{
	for (auto &&c : str)
	{
		if (0 != (c & 0x80))
			return false;
	}
	return true;
}

class IA5String final : public DerBase
{
public:
	// Needs to be constrained to ASCII range
	// International ASCII characters (International Alphabet 5)
	bool SetValue(std::string str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::IA5String,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const IA5String &str)
	{
		os << str.value;
		return os;
	}

	// friend std::wostream &operator<<(std::wostream &os, const IA5String &str)
	// {
	// 	os << utf8ToUtf16(str.value);
	// 	return os;
	// }

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class GeneralString final : public DerBase
{
public:
	// all registered graphic and character sets plus SPACE and DELETE
	bool SetValue(std::string str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::GeneralString,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const GeneralString &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const GeneralString &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class PrintableString final : public DerBase
{
public:
	bool SetValue(std::string str);

	// constrain to printable chars
	// a-z, A-Z, 0-9 ' () +,-.?:/= and SPACE

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::PrintableString,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const PrintableString &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const PrintableString &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class T61String final : public DerBase
{
public:
	// Arbitrary T.61 characters, likely obsolete
	bool SetValue(std::string str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::T61String,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const T61String &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const T61String &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

// Note - neither T61String or TeletexString are commonly used
// Teletex is CCITT and T.101 character sets
typedef T61String TeletexString;

class UTF8String final : public DerBase
{
public:
	// any character from a recognized alphabet (including ASCII control characters)
	bool SetValue(std::string str)
	{
		value = str;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::UTF8String,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const UTF8String &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const UTF8String &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class VisibleString final : public DerBase
{
public:
	// International ASCII printing character sets
	bool SetValue(std::string str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(std::span<std::byte> out) override;
	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::VisibleString,value);
	}

	friend std::ostream &operator<<(std::ostream &os, const VisibleString &str)
	{
		os << str.value;
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const VisibleString &str)
	{
		os << utf8ToUtf16(str.value);
		return os;
	}

	const std::string &ToString() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class UniversalString final : public DerBase
{
public:
	// ISO10646 character set
	// This is effectively UTF-32, and while I can write something that translates
	// back and forth to Unicode, that's work, and I don't have a cross-platform library
	// to do this right now. Also appears not to be used in signing.

	/* Can't be implemented without some work, not required at this time
	friend std::ostream& operator<<(std::ostream& os, const UniversalString& str)
	{
		os << str.value;
		return os;
	}
	*/

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::UniversalString,value);
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size() * sizeof(value[0])); }

	std::u32string value;
};

class BMPString final : public DerBase
{
public:
	friend std::ostream &operator<<(std::ostream &os, const BMPString &str)
	{
		auto stringValue = ConvertWstringToString(str.value);
		os << stringValue;
		return os;
	}

	// Basic Multilingual Plane of ISO/IEC/ITU 10646-1
	bool SetValue(const wchar_t *wz)
	{
		if (wz == nullptr)
			return false;

		value = wz;
		return true;
	}

	virtual size_t SetDataSize() override { return (cbData = value.size() * sizeof(wchar_t)); }

	virtual void Encode(std::span<std::byte> out) override;

	virtual bool Decode(DerDecode decoder) override
	{
		return decoder.Decode(DerType::BMPString,value);
	}

	std::wstring value;
};

class Null final : public DerBase
{
public:
	friend std::ostream &operator<<(std::ostream &os, const Null &)
	{
		os << "Null";
		return os;
	}

	friend std::wostream &operator<<(std::wostream &os, const Null &)
	{
		os << L"Null";
		return os;
	}

	virtual void Encode(std::span<std::byte> out) override
	{
		if (out.size() < 2)
			throw std::overflow_error("Overflow in Null::Encode");

		out[0] = static_cast<std::byte>(DerType::Null);
		out[1] = std::byte{0};
		cbData = 2;
	}

	virtual bool Decode(DerDecode decoder) override
	{
		auto remaining = decoder.RemainingData();
		// This one is special
		if (remaining.size() < 2 || remaining[0] != static_cast<std::byte>(DerType::Null) || remaining[1] != std::byte{0})
		{
			cbData = 0;
			return false;
		}

		cbData = 2;
		return true;
	}

	virtual size_t SetDataSize() override { return (cbData = 0); }
};

/* End basic DER encoding types */
