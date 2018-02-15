#pragma once

/* Start basic DER encoding types */

/*
	This is actually a bitfield, roughly defined as
	struct DerType
	{
		unsigned char class : 2,
		unsigned char constructed : 1, // Constructed = 1, Primitive = 0
		unsigned char tag : 5
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
	ObjectDescriptor = 7,  // Not used in signing, don't need encoder for now
	External = 8,  // Not used in signing, don't need encoder for now
	Real = 9,  // Not used in signing, don't need encoder for now
	Enumerated = 10,
	EmbeddedPDV = 11, // Not used in signing, don't need encoder for now
	UTF8String = 12, // Not used in signing, don't need encoder for now
	RelativeOid = 13, // Not used in signing, don't need encoder for now
	Reserved1 = 14, // reserved
	Reserved2 = 15, // reserved
	Sequence = 16, // also sequence of
	Set = 17, // also set of
	NumericString = 18, // Not used in signing, don't need encoder for now
	PrintableString = 19,
	T61String = 20, // Not used in signing, don't need encoder for now
	VideotexString = 21, // Not used in signing, don't need encoder for now
	IA5String = 22,
	UTCTime = 23,
	GeneralizedTime = 24,
	GraphicString = 25, // Not used in signing, don't need encoder for now
	VisibleString = 26,
	GeneralString = 27, // Not used in signing, don't need encoder for now
	UniversalString = 28, // Not used in signing, don't need encoder for now
	CharacterString = 29, // Not used in signing, don't need encoder for now
	BMPString = 30,
	Constructed = 0x20,
	ConstructedSequence = Constructed | Sequence,
	ConstructedSet = Constructed | Set
};

class DerTypeContainer
{
public:
	DerTypeContainer(unsigned char c) 
		: type(static_cast<DerType>(c & 0x1f)), 
		_class(static_cast<DerClass>((c & 0xc0) >> 6)),
		constructed(!!(c & 0x20))
	{

	}

	operator unsigned char()
	{
		return (static_cast<unsigned char>(_class) << 6) | (constructed ? 0x20 : 0) | (static_cast<unsigned char>(type));
	}

	friend std::ostream& operator<<(std::ostream& os, const DerTypeContainer& type);

	DerType type;
	DerClass _class;
	bool constructed;
};

inline size_t GetSizeBytes(unsigned long long size)
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

bool EncodeSize(size_t size, unsigned char* out, size_t cbOut, size_t& cbUsed);
bool DecodeSize(const unsigned char* in, size_t cbIn, size_t& size, size_t& cbRead);

void DebugDer(const unsigned char* pIn, size_t cbIn, unsigned long level = 0);

template <typename T>
void EncodeSet(std::vector<T>& in, unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbInternal = 0;
	size_t offset = 0;

	if (in.size() == 0)
	{
		if (cbOut < 2)
			throw std::overflow_error("Overflow in EncodeSet");

		pOut[0] = static_cast<unsigned char>(DerType::Null);
		pOut[1] = 0;
		cbUsed = 2;
		return;
	}

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSet);

	size_t cbVector = GetEncodedSize(in);

	offset = 1;
	if (!EncodeSize(cbVector, pOut + offset, cbOut - offset, cbInternal))
		throw std::exception("Error in EncodeSize");

	offset += cbInternal;

	for (unsigned int i = 0; i < in.size(); ++i)
	{
		in[i].Encode(pOut + offset, cbOut - offset, cbInternal);
		offset += cbInternal;
	}

	cbUsed = offset;
}

// Basic check for any type
inline bool CheckDecode(const unsigned char* pIn, size_t cbIn, const DerType type, size_t& size, size_t& cbPrefix)
{
	if (cbIn < 3 || pIn[0] != static_cast<unsigned char>(type))
	{
		cbPrefix = 0;
		return false;
	}

	if (!DecodeSize(pIn + 1, cbIn - 1, size, cbPrefix) || 1 + cbPrefix + size > cbIn)
		throw std::exception("Illegal size value");

	cbPrefix++;
	return true;
}

// Create an interface to ensure consistency

class AnyType;

// Note - at least some classes need a way to determine if an AnyType class holds that class

class DerBase
{
public:
	DerBase() : cbData(0) {}

	virtual size_t EncodedSize()
	{
		SetDataSize();
		return 1 + GetSizeBytes(cbData) + cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) = 0;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) = 0;

protected:
	virtual size_t SetDataSize() = 0;

	// This checks whether the tag is for a sequence, as expected, and if it is,
	// adjusts pIn and cbIn to only include the sequence
	bool DecodeSequenceOrSet(DerType type, const unsigned char* pIn, size_t cbIn, size_t& cbUsed, size_t& size, bool& isNull)
	{
		// Avoid complications - 

		if (DecodeNull(pIn, cbIn, cbUsed))
		{
			isNull = true;
			return true;
		}

		isNull = false;

		// Validate the sequence
		size = 0;
		size_t cbPrefix = 0;

		if (!CheckDecode(pIn, cbIn, type, size, cbPrefix))
		{
			cbUsed = 0;
			return false;
		}

		// Adjust these to start at the beginning of the sequence
		cbUsed = cbPrefix;
		return true;
	}

	bool DecodeSequence(const unsigned char* pIn, size_t cbIn, size_t& cbUsed, bool& isNull)
	{
		size_t size = 0;
		return DecodeSequenceOrSet(DerType::ConstructedSequence, pIn, cbIn, cbUsed, size, isNull);
	}

	template <typename T>
	bool DecodeSetOrSequenceOf(DerType type, const unsigned char* pIn, size_t cbIn, size_t& cbUsed, std::vector<T>& out)
	{
		bool isNull = false;
		size_t offset = 0;
		size_t size = 0;
		size_t cbPrefix;

		out.clear();

		if (!DecodeSequenceOrSet(type, pIn, cbIn, cbPrefix, size, isNull))
		{
			cbUsed = 0;
			return false;
		}

		if (isNull)
		{
			cbUsed = 2;
			return true;
		}

		offset = cbPrefix;

		for (;;)
		{
			size_t cbElement = 0;
			T t;

			if (offset > cbIn)
				throw std::exception("Integer overflow");

			if (!t.Decode(pIn + offset, cbIn - offset, cbElement))
				return false;

			offset += cbElement;
			out.push_back(t);

			// Exit conditions - should have used all of our
			// incoming data, as long as everything is polite
			if (offset == size + cbPrefix)
			{
				cbUsed = size + cbPrefix;
				return true;
			}
		}
	}

	template <typename T>
	bool DecodeSet(const unsigned char* pIn, size_t cbIn, size_t& cbUsed, std::vector<T>& out)
	{
		return 	DecodeSetOrSequenceOf(DerType::ConstructedSet, pIn, cbIn, cbUsed, out);
	}

	template <typename T>
	bool DecodeSequenceOf(const unsigned char* pIn, size_t cbIn, size_t& cbUsed, std::vector<T>& out)
	{
		return 	DecodeSetOrSequenceOf(DerType::ConstructedSequence, pIn, cbIn, cbUsed, out);
	}

	// Check for types that have a vector or a type of string

	bool DecodeNull(const unsigned char* pIn, size_t cbIn, size_t& cbUsed)
	{
		if (cbIn >= 2 && pIn[0] == static_cast<unsigned char>(DerType::Null) && pIn[1] == 0)
		{
			cbUsed = 2;
			return true;
		}
			
		cbUsed = 0;
		return false;
	}

	template <typename T>
	bool Decode(const unsigned char* pIn, size_t cbIn, const DerType type, size_t& cbUsed, T& value)
	{
		size_t size = 0;
		size_t cbPrefix = 0;

		value.clear();

		if (!CheckDecode(pIn, cbIn, type, size, cbPrefix))
		{
			// Allow Null, will correctly set cbUsed
			return DecodeNull(pIn, cbIn, cbUsed);
		}

		cbUsed = cbPrefix + static_cast<size_t>(size);
		value.insert(value.begin(), pIn + cbPrefix, pIn + cbUsed);
		return true;
	}

	// Don't calculate the data size more than once
	size_t cbData;
};

template <typename T>
class ContextSpecificHolder
{
public:
	ContextSpecificHolder(unsigned char _type) : type(_type) {}

	size_t EncodedSize()
	{
		size_t innerSize = innerType.EncodedSize();
		return 1 + GetSizeBytes(innerSize) + innerSize;
	}

	// This contains an encapsulated type, and it has a type
	// that is defined by the context
	bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
	{
		if (IsOptionPresent(*pIn))
		{
			size_t offset = 0;

			// Validate the sequence
			size_t size = 0;
			size_t cbPrefix = 0;

			if (!CheckDecode(pIn, cbIn, static_cast<const DerType>(*pIn), size, cbPrefix))
			{
				cbUsed = 0;
				return false;
			}

			offset += cbPrefix;
			// Now, we can decode the inner type
			if (innerType.Decode(pIn + offset, size, cbUsed))
			{
				cbUsed += cbPrefix;
				return true;
			}
		}

		return false;
	}

	void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed)
	{
		// Handle the case where there is no data, and we shouldn't write out anything
		size_t innerSize = innerType.EncodedSize();

		if (innerSize <= 2)
		{
			cbUsed = 0;
			return;
		}

		size_t cbSize = GetSizeBytes(innerSize);

		if (1 + cbSize + innerSize > cbOut)
		{
			throw std::exception("Insufficient buffer");
		}

		DerTypeContainer typeContainer(type);

		typeContainer.constructed = true;
		typeContainer._class = DerClass::ContextSpecific;

		size_t offset = 1;
		cbUsed = 0;

		*pOut = static_cast<unsigned char>(typeContainer);
		EncodeSize(innerSize, pOut + offset, cbOut - offset, cbUsed);

		offset += cbUsed;
		innerType.Encode(pOut + offset, cbOut - offset, cbUsed);

		cbUsed += offset;
	}

	bool IsOptionPresent(unsigned char c)
	{
		DerTypeContainer typeContainer(c);

		if (typeContainer.constructed &&
			typeContainer._class == DerClass::ContextSpecific &&
			typeContainer.type == static_cast<DerType>(type))
			return true;

		return false;
	}

private:
	T innerType;
	unsigned char type;
};

// In order for this to work without being overly clunky,
// this type will only hold encoded types
class AnyType final : public DerBase
{
public:
	// encode this to NULL if empty
	virtual size_t EncodedSize() { return encodedValue.size(); }

	void SetNull()
	{
		encodedValue.resize(2);
		encodedValue[0] = static_cast<unsigned char>(DerType::Null);
		encodedValue[1] = 0;
	}

	void SetEncodedValue(const unsigned char* pIn, size_t cbIn)
	{
		encodedValue.resize(cbIn);
		encodedValue.insert(encodedValue.begin(), pIn, pIn + cbIn);
	}

	void SetEncodedValue(std::vector<unsigned char>& lhs)
	{
		encodedValue.swap(lhs);
	}

	template <typename T>
	void SetValue(T& in)
	{
		size_t cbOut = in.EncodedSize();
		size_t cbUsed = 0;
		encodedValue.clear();
		encodedValue.resize(cbOut);

		in.Encode(&encodedValue[0], cbOut, cbUsed);
	}

	template <typename T>
	void SetValue(std::vector<T>& in)
	{
		if (in.size() == 0)
		{
			SetNull();
			return;
		}

		size_t cbDataIn = GetEncodedSize(in);
		size_t cbSize = GetSizeBytes(cbDataIn);
		size_t cbBuffer = cbDataIn + cbSize + 1;

		encodedValue.resize(cbBuffer);
		unsigned char* pBuffer = &encodedValue[0];
		size_t cbUsed = 0;
		EncodeSet(in, pBuffer, cbBuffer, cbUsed);
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		// Should be encoded already
		if (encodedValue.size() == 0)
			SetNull();

		memcpy_s(pOut, cbOut, &encodedValue[0], encodedValue.size());
		cbUsed = encodedValue.size();
	}

	bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
	{
		// This can hold anything, by design. Just copy the bytes, might be a Null
		if (cbIn < 2)
			return false;

		if (pIn[0] == static_cast<unsigned char>(DerType::Null))
		{
			if (pIn[1] == 0)
			{
				cbUsed = 2;
				return true;
			}
			return false;
		}
		else
		{
			size_t size = 0;
			size_t cbPrefix = 0;

			if (!DecodeSize(pIn + 1, cbIn - 1, size, cbPrefix) || 1 + cbPrefix + size > cbIn)
				throw std::exception("Illegal size value");

			encodedValue.clear();
			cbUsed = 1 + cbPrefix + static_cast<size_t>(size);
			encodedValue.insert(encodedValue.begin(), pIn, pIn + cbUsed);
			
			return true;
		}
	}

	const unsigned char* GetBuffer() const { return &encodedValue[0]; }
	size_t GetBufferSize() const { return encodedValue.size(); }

	// Shouldn't need this for this class, but everything needs it implemented
	virtual size_t SetDataSize() override;

	friend std::ostream& operator<<(std::ostream& os, const AnyType& o)
	{
		// TODO - this should be nicer
		for (size_t pos = 0; pos < o.encodedValue.size(); ++pos)
		{
			os << std::hex << o.encodedValue[pos] << " ";
		}

		return os;
	}

private:
	std::vector<unsigned char> encodedValue;
};

class Boolean final : public DerBase
{
public:
	Boolean(bool f = false)
	{
		if (f)
			b = 0xff;
		else
			b = 0;
	}

	void SetValue(bool f) { b = f ? 0xff : 0; }
	bool GetValue() const { return b == 0 ? false : true; }

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

	friend std::ostream& operator<<(std::ostream& os, const Boolean& b)
	{
		os << (b.b == 0 ? "false" : "true");
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = 1); }

	unsigned char b;
};

// Allowed to be any size
class Integer final : public DerBase
{
public:

	template <typename T>
	void SetValue(T in)
	{
		static_assert(std::is_integral<T>::value);

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
			T testBit = value >> (sizeof(T) * 8) - 1;

			if (testBit > 0)
				fAddLeadingZero = true;
		}

		value.resize(sizeof(T) + (fAddLeadingZero ? 1 : 0));

		if (fAddLeadingZero)
			value.push_back(0);

		unsigned char* pData = reinterpret_cast<unsigned char*>(&in);

		// Assuming that we're on a little-endian system, start at the end
		bool fHasData = false;

		for (int i = sizeof(T) - 1; i >= 0; --i)
		{
			// Discard leading zeros
			if (!fHasData && pData[i] == 0)
				continue;

			fHasData = true;
			value.push_back(pData[i]);
		}
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::Integer, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const Integer& o)
	{
		for (size_t pos = o.value.size(); pos > 0; --pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos-1] << " ";
		}

		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<unsigned char> value;
};

class BitString final : public DerBase
{
public:
	void SetValue(unsigned char unusedBits, const unsigned char* data, size_t cbData);

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	unsigned char UnusedBits() const { return value.size() > 0 ? value[0] : 0; }

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::BitString, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const BitString& o)
	{
		const unsigned long linelength = 80;
		const unsigned long blocksperline = linelength / sizeof(size_t);

		unsigned long cBlocks = o.value.size() / sizeof(size_t);
		unsigned long cRemaining = o.value.size() % sizeof(size_t);
		const size_t* pData = reinterpret_cast<const size_t*>(&o.value[0]);
		std::ostringstream osTmp;

		osTmp << std::endl;

		for (size_t pos = 0; pos < cBlocks; ++pos)
		{
			if (pos > 0 && (pos % blocksperline) == 0)
				osTmp << std::endl;

			osTmp << std::setfill('0') << std::setw(sizeof(size_t)*2) << std::hex << pData[pos];
		}

		for (size_t pos = 0; pos < cRemaining; ++pos)
		{
			osTmp << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[cBlocks * sizeof(size_t) + pos];
		}

		os << osTmp.str() << std::endl;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<unsigned char> value;
};

class OctetString final : public DerBase
{
public:
	void SetValue(const unsigned char* data, size_t cb)
	{
		value.clear();
		value.resize(cb);
		value.insert(value.begin(), data, data + cb);
	}
	
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::OctetString, cbUsed, value);
	}
	
	friend std::ostream& operator<<(std::ostream& os, const OctetString& o)
	{
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos] << " ";
		}

		os << std::setfill(' ');
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<unsigned char> value;
};

class Enumerated : public DerBase
{
public:
	Enumerated(unsigned char v = 0xff) : value(v) {}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		size_t size = 0;
		size_t cbPrefix = 0;
		if (!CheckDecode(pIn, cbIn, DerType::Boolean, size, cbPrefix))
		{
			cbUsed = 0;
			return false;
		}

		// Now check specifics for this type
		if (cbPrefix + size != 3)
			throw std::exception("Incorrect decode");

		value = pIn[2];
		cbUsed = 3;
		return true;
	}

	friend std::ostream& operator<<(std::ostream& os, const Enumerated& e)
	{
		os << e.value;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = 1); }

	unsigned char value;
};

class ObjectIdentifier final : public DerBase
{
public:
	ObjectIdentifier(const char* szOid)
	{
		SetValue(szOid);
	}

	ObjectIdentifier() = default;

	bool ToString(std::string& out) const;
	void SetValue(const char* szOid);

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::ObjectIdentifier, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const ObjectIdentifier& obj)
	{
		std::string s;
		obj.ToString(s);

		os << s;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	void EncodeLong(unsigned long in, unsigned char* out, size_t cbOut, size_t& cbUsed);
	bool DecodeLong(const unsigned char* in, size_t cbIn, unsigned long& out, size_t& cbRead) const;
	void GetNextLong(const char* start, const char*& next, unsigned long& out);

	std::vector<unsigned char> value;

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

	bool SetValue(tm* gmt)
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
	
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::UTCTime, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const UTCTime& str)
	{
		os << str.value;
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

	bool SetValue(tm* gmt)
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


	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::GeneralizedTime, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const GeneralizedTime& str)
	{
		os << str.value;
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

	friend std::ostream& operator<<(std::ostream& os, const Time& str)
	{
		os << str.value;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
	TimeType type;
};

/*
For documentation on string types, see:
https://www.obj-sys.com/asn1tutorial/node128.html
*/

inline bool IsAscii(const char* str)
{
	for (; *str != '\0'; ++str)
	{
		if (static_cast<unsigned char>(*str) & 0x80)
			return false;
	}
	return true;
}

class IA5String final : public DerBase
{
public:
	// Needs to be constrained to ASCII range
	// International ASCII characters (International Alphabet 5)
	bool SetValue(const char* str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::IA5String, cbUsed, value);
	}
	
	friend std::ostream& operator<<(std::ostream& os, const IA5String& str)
	{
		os << str.value;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class GeneralString final : public DerBase
{
public:
	// all registered graphic and character sets plus SPACE and DELETE
	bool SetValue(const char* str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::GeneralString, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const GeneralString& str)
	{
		os << str.value;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class PrintableString final : public DerBase
{
public:
	bool SetValue(const char* str);

	// constrain to printable chars
	// a-z, A-Z, 0-9 ' () +,-.?:/= and SPACE

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::PrintableString, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const PrintableString& str)
	{
		os << str.value;
		return os;
	}

private:

	virtual size_t SetDataSize() override { return (cbData = value.size()); }
	
	std::string value;
};

class T61String final : public DerBase
{
public:
	// Arbitrary T.61 characters, likely obsolete
	bool SetValue(const char* str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::T61String, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const T61String& str)
	{
		os << str.value;
		return os;
	}

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
	bool SetValue(const char* str)
	{
		if (str == nullptr)
			return false;

		value = str;
		return true;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::UTF8String, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const UTF8String& str)
	{
		os << str.value;
		return os;
	}

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::string value;
};

class VisibleString final : public DerBase
{
public:
	// International ASCII printing character sets 
	bool SetValue(const char* str)
	{
		if (!IsAscii(str))
			return false;

		value = str;
		return true;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::VisibleString, cbUsed, value);
	}

	friend std::ostream& operator<<(std::ostream& os, const VisibleString& str)
	{
		os << str.value;
		return os;
	}

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::UniversalString, cbUsed, value);
	}


private:
	virtual size_t SetDataSize() override { return (cbData = value.size() * sizeof(value[0])); }

	std::u32string value;
};

class BMPString final : public DerBase
{
public:
	friend std::ostream& operator<<(std::ostream& os, const BMPString& str)
	{
		//setup converter
		using convert_type = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type, wchar_t> converter;

		//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
		std::string converted_str = converter.to_bytes(str.value);

		os << converted_str;
		return os;
	}

	// Basic Multilingual Plane of ISO/IEC/ITU 10646-1
	bool SetValue(const wchar_t* wz) 
	{
		if (wz == nullptr)
			return false;

		value = wz; 
		return true;
	}

	virtual size_t SetDataSize() override { return (cbData = value.size() * sizeof(wchar_t)); }

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DerBase::Decode(pIn, cbIn, DerType::BMPString, cbUsed, value);
	}

	std::wstring value;
};

class Null final : public DerBase
{
public:

	friend std::ostream& operator<<(std::ostream& os, const Null& )
	{
		os << "Null";
		return os;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		if(cbOut < 2)
			throw std::overflow_error("Overflow in Null::Encode");

		pOut[0] = static_cast<unsigned char>(DerType::Null);
		pOut[1] = 0;
		cbUsed = 2;
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		// This one is special
		if (cbIn < 2 || pIn[0] != static_cast<unsigned char>(DerType::Null) || pIn[1] != 0)
		{
			cbUsed = 0;
			return false;
		}

		cbUsed = 2;
		return true;
	}

	virtual size_t SetDataSize() override { return (cbData = 0); }
};


/* End basic DER encoding types */
