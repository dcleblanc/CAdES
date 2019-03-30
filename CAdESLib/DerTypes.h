// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
    TeletexString = 20, // An alias for T61String
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

void DebugDer(std::ostream& outFile, const unsigned char* pIn, size_t cbIn, unsigned long level = 0);

template <typename T>
void EncodeSetOrSequenceOf(DerType type, std::vector<T>& in, unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbInternal = 0;
	size_t offset = 0;

	if (in.size() == 0)
	{
		if (cbOut < 2)
			throw std::overflow_error("Overflow in EncodeSetOrSequenceOf");

		pOut[0] = static_cast<unsigned char>(DerType::Null);
		pOut[1] = 0;
		cbUsed = 2;
		return;
	}

	pOut[0] = static_cast<unsigned char>(type);

	size_t cbVector = GetEncodedSize(in);

	offset = 1;
	if (!EncodeSize(cbVector, pOut + offset, cbOut - offset, cbInternal))
		throw std::out_of_range("Error in EncodeSize");

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
    // Check for sufficient incoming bytes
    if (cbIn >= 3 && 
        // If it is context-specific, allow it, else verify that it is the type we expect
        ((pIn[0] & 0x80) || pIn[0] == static_cast<unsigned char>(type)) )
    {
        if (!DecodeSize(pIn + 1, cbIn - 1, size, cbPrefix) || 1 + cbPrefix + size > cbIn)
            throw std::out_of_range("Illegal size value");

        cbPrefix++;
        return true;
    }
    else if (cbIn == 2 && pIn[1] == 0)
    {
        // Zero length sequence, which can happen if the first member has a default, and the remaining are optional
        size = 2;
        cbPrefix = 2;
        return true;
    }

	cbPrefix = 0;
	return false;
}

// Create an interface to ensure consistency

class AnyType;

// Note - at least some classes need a way to determine if an AnyType class holds that class

class DerBase
{
    friend class SequenceHelper;

public:
	DerBase() : cbData(0) {}

	virtual size_t EncodedSize() const
	{
		// No longer calling SetDataSize here
		// If the object is already fully loaded, then we know cbData, and don't need to 
		// take the perf hit of recalculating it.
		// If it has been set some other way, say we're building the object 
		// directly, then call SetDataSize when you're done.
		return 1 + GetSizeBytes(cbData) + cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) = 0;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) = 0;

	template <typename T>
	static bool DecodeSet(const unsigned char* pIn, size_t cbIn, size_t& cbUsed, std::vector<T>& out)
	{
		size_t cbPrefix = 0;
		size_t cbSize = 0;
		bool ret = DecodeSetOrSequenceOf(DerType::ConstructedSet, pIn, cbIn, cbPrefix, cbSize, out);

		if (ret)
			cbUsed = cbPrefix + cbSize;

		return ret;
	}

    template <typename T>
    static bool DecodeSet(const unsigned char* pIn, size_t cbIn, size_t& cbPrefix, size_t& cbSize, std::vector<T>& out)
    {
        return 	DecodeSetOrSequenceOf(DerType::ConstructedSet, pIn, cbIn, cbPrefix, cbSize, out);
    }

    template <typename T>
    static bool DecodeSequenceOf(const unsigned char* pIn, size_t cbIn, size_t& cbPrefix, size_t& cbSize, std::vector<T>& out)
    {
        return 	DecodeSetOrSequenceOf(DerType::ConstructedSequence, pIn, cbIn, cbPrefix, cbSize, out);
    }

	size_t GetcbData() const { return cbData; }

protected:
	virtual size_t SetDataSize() = 0;

    void CheckOutputSize(size_t cbUsed)
    {
        if (1 + GetSizeBytes(cbData) + cbData != cbUsed)
            throw std::out_of_range("Size mismatch!");
    }

    static bool DecodeSequence(const unsigned char* pIn, size_t cbIn, size_t& cbUsed, size_t& size, bool& isNull)
    {
        return DecodeSequenceOrSet(DerType::ConstructedSequence, pIn, cbIn, cbUsed, size, isNull);
    }

	// This checks whether the tag is for a sequence, as expected, and if it is,
	// adjusts pIn and cbIn to only include the sequence
	static bool DecodeSequenceOrSet(DerType type, const unsigned char* pIn, size_t cbIn, size_t& cbUsed, size_t& size, bool& isNull)
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

	template <typename T>
	static bool DecodeSetOrSequenceOf(DerType type, const unsigned char* pIn, size_t cbIn, size_t& cbPrefix, size_t& cbSize, std::vector<T>& out)
	{
		bool isNull = false;
		size_t offset = 0;

		out.clear();

		if (!DecodeSequenceOrSet(type, pIn, cbIn, cbPrefix, cbSize, isNull))
		{
			cbPrefix = 0;
			cbSize = 0;
			return false;
		}

		if (isNull)
		{
			cbPrefix = 2;
			cbSize = 0;
			return true;
		}

		offset = cbPrefix;
        cbIn = cbPrefix + cbSize;

		for (;;)
		{
			size_t cbElement = 0;
			T t;

			if (offset > cbIn)
				throw std::overflow_error("Integer overflow");

			if (!t.Decode(pIn + offset, cbIn - offset, cbElement))
				return false;

			offset += cbElement;
			out.push_back(t);

			// Exit conditions - should have used all of our
			// incoming data, as long as everything is polite
			if (offset == cbSize + cbPrefix)
			{
				return true;
			}
		}
	}

	// Check for types that have a vector or a type of string
	static bool DecodeNull(const unsigned char* pIn, size_t cbIn, size_t& cbUsed)
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
		cbData = value.size();
		return true;
	}

	// Don't calculate the data size more than once
	size_t cbData;
};

enum class DecodeResult
{
    Failed,
    Null,
    EmptySequence,
    Success
};

class SequenceHelper
{
public:
    SequenceHelper(size_t& _cbUsed) : dataSize(0), prefixSize(0), isNull(false), cbUsed(_cbUsed), cbCurrent(0) {}

    // Note - because CheckExit throws, the destructor must also be marked as throwing
    // or we will land in terminate and not the catch block.
    ~SequenceHelper() noexcept(false)
    {
        Update();
        CheckExit();
        cbUsed += prefixSize;
    }

    DecodeResult Init(const unsigned char * pIn, size_t cbIn, size_t& _dataSize)
    {
        // This checks internally to see if the data size is within bounds of cbIn
        if (!DerBase::DecodeSequence(pIn, cbIn, cbUsed, dataSize, isNull))
            return DecodeResult::Failed;

        if (isNull)
            return DecodeResult::Null;

        if (cbUsed == cbIn)
            return DecodeResult::EmptySequence;

        prefixSize = cbUsed;
		_dataSize = dataSize;
        cbUsed = 0; // Let cbUsed now track just the amount of remaining data
        return DecodeResult::Success;
    }

    void CheckExit() noexcept(false)
    {
        // if it isn't an error return, then make sure we've consumed all the data
        if (!isNull && cbUsed != dataSize)
            throw std::runtime_error("Parsing error");
    }

    const unsigned char* DataPtr(const unsigned char * pIn) const { return pIn + cbUsed + prefixSize; }

    size_t DataSize() 
    { 
        if (cbUsed > dataSize)
            throw std::overflow_error("Integer overflow in data size");

        return dataSize - cbUsed;
    }

    void Update() 
    { 
        cbUsed += cbCurrent; 
        cbCurrent = 0;
    }

    size_t& CurrentSize() { return cbCurrent; }
    bool IsAllUsed() const { return cbUsed == dataSize; }

private:
    size_t dataSize;
    size_t prefixSize;
    size_t cbCurrent;
    size_t& cbUsed;
    bool isNull;
};

class EncodeHelper
{
public:
    EncodeHelper(size_t& _cbUsed) : offset(0), cbNeeded(0), cbCurrent(0), cbUsed(_cbUsed){}
	~EncodeHelper() {}

    void Init(size_t _cbNeeded, unsigned char* pOut, size_t cbOut, unsigned char type, size_t cbData)
    { 
        cbNeeded = _cbNeeded; 
        if(cbNeeded > cbOut || cbOut < 2)
            throw std::overflow_error("Overflow in Encode");

        // Set the type
        *pOut = type;
        offset = 1;

        EncodeSize(cbData, DataPtr(pOut), DataSize(), CurrentSize());
        Update();
    }

	// This MUST be called before going out of scope
	// the method may throw, and if the throw were to happen in the destructor
	// it can't be caught, and debugging becomes difficult
	void Finalize()
	{
		Update();
		CheckExit();
		cbUsed = offset;
	}

    void Update()
    {
        offset += cbCurrent;
        cbCurrent = 0;
    }

    void CheckExit()
    {
        if (offset != cbNeeded)
            throw std::runtime_error("Size needed not equal to size used");
            // std::cout << "Size needed not equal to size used" << std::endl;
    }

    unsigned char* DataPtr(unsigned char * pOut) const { return pOut + offset; }

    size_t DataSize()
    {
        if(offset > cbNeeded)
            throw std::overflow_error("Integer overflow in data size");

        return cbNeeded - offset;
    }

    size_t& CurrentSize() { return cbCurrent; }

private:
    size_t offset;
    size_t cbNeeded;
    size_t cbCurrent;
    size_t& cbUsed;
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


template <typename T, unsigned char type, OptionType optionType>
class ContextSpecificHolder;

template <typename T, unsigned char type>
class ContextSpecificHolder <T, type, OptionType::Explicit>
{
public:
	ContextSpecificHolder() : hasData(false) {}

	size_t EncodedSize()
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
	bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
	{
        // If this is an optional type, we could have used
        // all the bytes on the previous item
        if (cbIn == 0)
            throw std::out_of_range("Insufficient buffer");

        if (pIn[0] == type)
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
                hasData = true;
                return true;
            }
        }

        cbUsed = 0;
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
			throw std::out_of_range("Insufficient buffer");
		}

        size_t offset = 1;
        cbUsed = 0;

        *pOut = type;
        EncodeSize(innerSize, pOut + offset, cbOut - offset, cbUsed);

        offset += cbUsed;
        innerType.Encode(pOut + offset, cbOut - offset, cbUsed);

        cbUsed += offset;
	}

    const T& GetInnerType() const { return innerType; }
    bool HasData() const { return hasData; }

private:

	T innerType;
    bool hasData;
};

template <typename T, unsigned char type>
class ContextSpecificHolder <T, type, OptionType::Implicit>
{
public:
    ContextSpecificHolder() : hasData(false) {}

    size_t EncodedSize() 
	{
		if (innerType.GetcbData() == 0)
			return 0;

		return innerType.EncodedSize(); 
	}

    bool IsPresent(unsigned char t) const { return t == type; }

    bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
    {
        // If this is an optional type, we could have used
        // all the bytes on the previous item
        if (cbIn == 0)
            throw std::out_of_range("Insufficient buffer");

        if (IsPresent(pIn[0]))
        {
            bool fRet = innerType.Decode(pIn, cbIn, cbUsed);
            hasData = fRet;
            return fRet;
        }

        cbUsed = 0;
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
            throw std::out_of_range("Insufficient buffer");
        }

        // A non-constructed type is the same as the type it wraps, 
        // except for the type byte, which will be ([0x80 or 0xA0] | option number)
        innerType.Encode(pOut, cbOut, cbUsed);
        *pOut = static_cast<unsigned char>(type);
    }

    const T& GetInnerType() const { return innerType; }
    T& GetInnerType() { return innerType; }

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
	virtual size_t EncodedSize() 
    {
        if (encodedValue.size() == 0)
            SetNull();

        return encodedValue.size(); 
    }

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
				throw std::out_of_range("Illegal size value");

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

    static std::ostream& Output(std::ostream& os, const AnyType& o);

	friend std::ostream& operator<<(std::ostream& os, const AnyType& o)
	{
        return Output(os, o);
	}

    bool ToString(std::string& out) const;

    DerType GetDerType() const { return encodedValue.size() > 1 ? static_cast<DerType>(encodedValue[0]) : DerType::Null; }

    const AnyType& operator=(const AnyType& rhs) { encodedValue = rhs.encodedValue; return *this; }
    const std::vector<unsigned char>& GetData() const { return encodedValue; }

    template <typename T>
    bool ConvertToType(T& type) const
    {
        size_t cbUsed = 0;
        return type.Decode(&encodedValue[0], encodedValue.size(), cbUsed) && cbUsed == encodedValue.size();
    }

    template <typename T>
    bool OutputFromType(std::ostream& os) const 
    {
        T t;
        bool fConverted = ConvertToType(t);
        if (fConverted)
            os << t;

        return fConverted;
    }

private:
	std::vector<unsigned char> encodedValue;
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
    ChoiceType() : derType(0xff){}

    virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
    {
        value.Encode(pOut, cbOut, cbUsed);
    }

    virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
    {
        if (value.Decode(pIn, cbIn, cbUsed))
        {
            derType = *pIn;
            return true;
        }

        return false;
    }

    const AnyType& GetValue() const { return value; }

    // It appears that these are EXPLICIT, at least GeneralName is
    bool GetInnerType(AnyType& inner)
    {
        size_t cbUsed = 0;
        SequenceHelper sh(cbUsed);
        const unsigned char* pIn = value.GetBuffer();

        switch (sh.Init(pIn, value.GetBufferSize(), this->cbData))
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
            return true;
        case DecodeResult::Success:
            break;
        }

        return inner.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize());
    }

    const unsigned char* GetInnerBuffer(size_t& innerSize) const
    {
        const unsigned char* pIn = value.GetBuffer();
        size_t cbIn = value.GetBufferSize();
        size_t cbPrefix = 0;

        innerSize = 0;

        if (!DecodeSize(pIn + 1, cbIn - 1, innerSize, cbPrefix) || 1 + cbPrefix + innerSize > cbIn)
            throw std::out_of_range("Illegal size value");

        return pIn + cbPrefix + 1;
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
		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		return os;
	}

    size_t ByteCount() const { return value.size(); }

    bool GetValue(unsigned long& data) const
    {
        size_t cbValue = value.size();

        if (cbValue == 0)
            return false;

        // Test for leading zero
        const unsigned char* pData = &value[0];

        if (*pData == 0)
        {
            ++pData;
            --cbValue;
        }

        if (cbValue > 4)
            return false;

        data = 0;
        for (size_t i = 0; i < cbValue; ++i)
        {
            data += *pData;
            if (i < cbValue - 1)
                data <<= 8;
        }

        return true;
    }

    const std::vector<unsigned char>& GetBytes() const { return value; }

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

    size_t ValueSize() const
    {
        if (value.size() < 2)
            return 0;
        
        unsigned char unusedBits = value[0];
        return value.size() * 8 - unusedBits;
    }

    bool GetValue(unsigned char& unusedBits, std::vector<unsigned char>& out) const 
    {
        if (value.size() < 2)
            return false;

        unusedBits = value[0];
        out.clear();
        out.resize(value.size() - 1);
        out.insert(out.begin(), value.begin() + 1, value.end());
        return true;
    }

    bool GetValue(const unsigned char*& pValue, size_t& cbValue)
    {
        if (value.size() < 2)
            return false;

        pValue = &value[0];
        cbValue = value.size();
        return true;
    }

	friend std::ostream& operator<<(std::ostream& os, const BitString& o)
	{
		const unsigned long linelength = 80;
		const unsigned char* pData = &o.value[0];
		std::ostringstream osTmp;

		for (size_t pos = 0; pos < o.value.size(); ++pos)
		{
            if (pos > 0 && (pos % linelength) == 0)
                osTmp << std::endl;

            // This is done byte by byte
			osTmp << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)pData[pos];
		}

        os << osTmp.str();
		return os;
	}

    const std::vector<unsigned char>& GetBits() const { return value; }

private:
	virtual size_t SetDataSize() override { return (cbData = value.size()); }

	std::vector<unsigned char> value;
};

class OctetString final : public DerBase
{
public:

    void SetValue(const std::vector<unsigned char>& in)
    {
        value = in;
    }

	void SetValue(const unsigned char* data, size_t cb)
	{
		value.clear();
		value.resize(cb);
		value.insert(value.begin(), data, data + cb);
	}

    // For use by extensions, which need to write
    // internal structs into the buffer.
    std::vector<unsigned char>& Resize(size_t cb)
    {
        value.clear();
        value.resize(cb);
        return value;
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
			os << std::setfill('0') << std::setw(2) << std::hex << (unsigned short)o.value[pos];
		}

		os << std::setfill(' ');
		return os;
	}

    const std::vector<unsigned char>& GetValue() const { return value; }

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
			throw std::length_error("Incorrect decode");

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
	ObjectIdentifier(const char* szOid) : oidIndex(OidIndexUnknown)
	{
		SetValue(szOid);
	}

	ObjectIdentifier() = default;

    static const size_t OidIndexUnknown = ~static_cast<size_t>(0);

	bool ToString(std::string& out) const;
	void SetValue(const char* szOid);

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
        bool fRet = DerBase::Decode(pIn, cbIn, DerType::ObjectIdentifier, cbUsed, value);

        if(fRet)
            SetOidIndex();

        return fRet;
	}

	friend std::ostream& operator<<(std::ostream& os, const ObjectIdentifier& obj)
	{
		std::string s;
		obj.ToString(s);

		os << s;
		return os;
	}

    const char* GetOidLabel() const 
    {
        // This will internally ignore invalid values to return null
        return ::GetOidLabel(oidIndex);
    }

    const char* GetOidString() const
    {
        return ::GetOidString(oidIndex);
    }

    std::vector<unsigned char>& GetBytes() { return value; }

    bool IsEmpty() const { return value.size() == 0; }

    const ObjectIdentifier& operator=(const ObjectIdentifier& rhs)
    {
        value = rhs.value;
        oidIndex = rhs.oidIndex;
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

	void EncodeLong(unsigned long in, unsigned char* out, size_t cbOut, size_t& cbUsed);
	bool DecodeLong(const unsigned char* in, size_t cbIn, unsigned long& out, size_t& cbRead) const;
	void GetNextLong(const char* start, const char*& next, unsigned long& out);

	std::vector<unsigned char> value;
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

    bool ToString(std::string& out) const;
    const std::string& GetValue() const { return value; }
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

    const std::string& ToString() const { return value; }

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

    const std::string& ToString() const { return value; }

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

    const std::string& ToString() const { return value; }

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

    const std::string& ToString() const { return value; }

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

    const std::string& ToString() const { return value; }

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

    const std::string& ToString() const { return value; }

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
		std::string converted_str;

		ConvertWstringToString(str.value, converted_str);
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

