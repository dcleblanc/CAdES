#pragma once

#include "Common.h"

enum class DecodeResult
{
    Failed,
    Null,
    EmptySequence,
    Success
};

class DerDecode
{
public:
    DerDecode(std::span<const std::byte> in)
        : in(in), remaining(in), prefixSize(0)
    {
    }

    DerDecode() = default;
    ~DerDecode() = default;
    DerDecode(DerDecode &&rhs) = default;
    DerDecode(const DerDecode &) = default;
    DerDecode &operator=(const DerDecode &rhs) = default;
    DerDecode &operator=(DerDecode &&rhs) = default;

    // Basic check for any type
    inline bool CheckDecode(std::span<const std::byte> bytesToValidate, DerType type, size_t &cbPrefix)
    {
        //size_t size = 0;
        // Check for sufficient incoming bytes
        if (bytesToValidate.size() >= 3 &&
            // If it is context-specific, allow it, else verify that it is the type we expect
            (std::byte{0} != (bytesToValidate[0] & std::byte{0x80}) || bytesToValidate[0] == static_cast<std::byte>(type)))
        {
            //if (!DecodeSize(bytesToValidate.subspan(1), size, cbPrefix) || 1 + cbPrefix + size > bytesToValidate.size())
            // if (!DecodeSize(size) || 1 + cbPrefix + size > bytesToValidate.size())
            //     throw std::out_of_range("Illegal size value");

            cbPrefix++;
            return true;
        }
        else if (bytesToValidate.size() == 2 && bytesToValidate[1] == std::byte{0})
        {
            // Zero length sequence, which can happen if the first member has a default, and the remaining are optional
            cbPrefix = 2;
            return true;
        }

        cbPrefix = 0;
        return false;
    }

    template <typename T, typename Char = void, typename Traits = void>
    bool Decode(const DerType type, T &value)
    {
        size_t cbPrefix = 0;

        if (!CheckDecode(remaining, type, cbPrefix))
        {
            // Allow Null, will correctly set cbData
            return DecodeNull();
        }

        remaining = remaining.subspan(cbPrefix);

        size_t size = 0;
        if (!DecodeSize(size) || size > remaining.size())
        {
            return false;
        }
        std::span<const std::byte> intBytes;
        if (!GetNextBytes(size, intBytes)) {
            return false;
        }
        
        DerDecode innerDecoder{intBytes};

        innerDecoder.DecodeInner(value);

        return true;
    }

    // This contains an encapsulated type, and it has a type
    // that is defined by the context
    template <typename T, std::byte type>
    bool Decode(T &innerType, bool &hasData)
    {
        hasData = false;
        // If this is an optional type, we could have used
        // all the bytes on the previous item
        if (remaining.size() == 0)
            throw std::out_of_range("Insufficient buffer");

        if (remaining[0] == type)
        {
            remaining = remaining.subspan(1);
            size_t cbPrefix = 0;

            if (!CheckDecode(remaining, static_cast<const DerType>(remaining[0]), cbPrefix))
            {
                return false;
            }

            remaining = remaining.subspan(cbPrefix);
            // Now, we can decode the inner type
            if (innerType.Decode(*this))
            {
                hasData = true;
                return true;
            }
        }

        return false;
    }

    std::tuple<DecodeResult, DerDecode> InitSequenceOrSet()
    {
        size_t size = 0;
        std::span<const std::byte> sequenceBytes;
        // This checks internally to see if the data size is within bounds of remaining.size()
        if (!DecodeSequenceOrSet(DerType::ConstructedSequence, size) 
        || !GetNextBytes(size, sequenceBytes))
            return std::tuple{DecodeResult::Failed, *this};

        if (size == 0)
            return std::tuple{DecodeResult::Null, *this};

        DerDecode sequenceDecoder{sequenceBytes};
        if (sequenceDecoder.Empty())
            return std::tuple{DecodeResult::EmptySequence, sequenceDecoder};

        return std::tuple{DecodeResult::Success, sequenceDecoder};
    }

    std::span<const std::byte> InitialData() const { return in; }
    std::span<const std::byte> RemainingData() const { return remaining; }

    // Check for types that have a vector or a type of string
    inline bool DecodeNull()
    {
        if (remaining.size() >= 2 && remaining[0] == static_cast<std::byte>(DerType::Null) && remaining[1] == std::byte{0})
        {
            remaining = remaining.subspan(2);
            return true;
        }

        return false;
    }

    inline bool DecodeSize(size_t &size)
    {
        size = 0;

        if (remaining.size() == 0)
        {
            return false;
        }

        // Detect short form
        if ((remaining[0] & std::byte{0x80}) == std::byte{0})
        {
            size = std::to_integer<size_t>(remaining[0]);
            remaining = remaining.subspan(1);
            return true;
        }

        auto bytesToDecode = std::to_integer<size_t>(remaining[0] & ~std::byte{0x80});
        uint64_t tmp = 0;

        // Decode a maximum of 8 bytes, which adds up to a 56-bit number
        // That's MUCH bigger than anything we could possibly decode
        // And bytes to decode has to be at least one, or it isn't legal
        // Note - the case of 1 happens when you have a length between 128 and 255,
        // so the high bit is set, which precludes short form, resulting in a pattern of 0x81, 0x8b
        // to encode the value of 139.
        if (bytesToDecode > 8 || bytesToDecode >= remaining.size() || bytesToDecode == 0)
            return false;

        for (size_t i = 1; i <= bytesToDecode; ++i)
        {
            tmp += std::to_integer<uint8_t>(remaining[i]);

            if (i < bytesToDecode)
                tmp <<= 8;
        }
        remaining = remaining.subspan(bytesToDecode + 1); // + 1 for the initial byte

        // We now have the size in a 64-bit value, check whether it fits in a size_t
        // Arbitrarily say that max size is 1/2 SIZE_T_MAX
        size_t maxSize = (~(static_cast<size_t>(0))) >> 1;

        if (tmp > maxSize)
        {
            return false;
        }

        size = tmp;
        return true;
    }

    template <typename T>
    bool DecodeSet(std::vector<T> &out)
    {
        size_t cbPrefix = 0;
        size_t cbSize = 0;

        if (DecodeSetOrSequenceOf(DerType::ConstructedSet, cbSize, out))
        {
            remaining = remaining.subspan(cbPrefix + cbSize);
            return true;
        }

        return false;
    }

    template <typename T>
    bool DecodeSequenceOf(size_t &cbSize, std::vector<T> &out)
    {
        return DecodeSetOrSequenceOf(DerType::ConstructedSequence, cbSize, out);
    }

    bool GetNextBytes(size_t size, std::span<const std::byte> &nextBytes)
    {
        if (remaining.size() < size)
        {
            return false;
        }

        nextBytes = remaining.subspan(0, size);
        remaining = remaining.subspan(size);
        return true;
    }

    bool Empty() const { return remaining.size() < 2; }

    // Used to help work with optional cases
    // where we don't know that it was optional until we decode into it
    void Reset()
    {
        remaining = in;
    }

private:
    std::span<const std::byte> in;
    std::span<const std::byte> remaining;
    size_t prefixSize;

    // This checks whether the tag is for a sequence, as expected, and if it is,
    // adjusts remaining to only include the sequence
    bool DecodeSequenceOrSet(DerType type, size_t &size)
    {
        // Avoid complications -
        if (DecodeNull())
        {
            size = 0;
            return true;
        }

        // Validate the sequence
        size_t cbPrefix = 0;

        if (!CheckDecode(remaining, type, cbPrefix))
        {
            return false;
        }

        // Adjust remaining data to start at the beginning of the sequence
        remaining = remaining.subspan(cbPrefix);

        if (!DecodeSize(size))
        {
            return false;
        }
        return true;
    }

    template <typename T>
    bool DecodeSetOrSequenceOf(DerType type, size_t &size, std::vector<T> &out)
    {
        out.clear();
        if (!DecodeSequenceOrSet(type, size))
        {
            size = 0;
            return false;
        }

        // null takes two bytes but has zero in the set/sequence
        if (size == 0)
        {
            size = 2;
            return true;
        }

        //offset = cbPrefix;
        //in.size() = cbPrefix + cbSize;
        std::span<const std::byte> setBytes;
        if (!GetNextBytes(size, setBytes))
        {
            throw std::overflow_error("Not enough bytes remain for the sequence");
        }

        DerDecode decoder{setBytes};
        while (!decoder.Empty())
        {
            // size_t cbElement = 0;
            T t;

            // if (offset > in.size())
            //     throw std::overflow_error("Integer overflow");

            if (!t.Decode(decoder))
            {
                // Accomodate the case where we have to decode into the
                // sequence to see if the element is optional
                // if (cbElement == 0)
                // {
                //     cbPrefix = 0;
                // }
                size = 0;
                return false;
            }

            // offset += cbElement;
            out.push_back(t);

            // Exit conditions - should have used all of our
            // incoming data, as long as everything is polite
            // if (offset == cbSize + cbPrefix)
            // {
            //     return true;
            // }
        }
        return true;
    }

    void DecodeInner(std::vector<std::byte> &value)
    {
        value = std::vector<std::byte>{remaining.begin(), remaining.end()};
    }

    void DecodeInner(std::span<const std::byte> &value)
    {
        value = remaining;
    }

    template <typename CharType>
    void DecodeInner(std::basic_string<CharType> &value)
    {
        auto pIn = reinterpret_cast<const CharType *>(remaining.data());
        auto stringView = std::basic_string_view<CharType>{pIn, remaining.size()};
        value = std::basic_string<CharType>{stringView.begin(), stringView.end()};
    }
};
