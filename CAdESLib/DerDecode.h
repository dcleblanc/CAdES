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

    ~DerDecode() = default;
    DerDecode(DerDecode &&rhs) = default;
    DerDecode(const DerDecode &) = default;
    DerDecode &operator=(const DerDecode &rhs) = delete;
    DerDecode &operator=(DerDecode &&rhs) = delete;

    // Basic check for any type
    bool CheckDecode(std::span<const std::byte> bytesToValidate, DerType type, size_t &cbPrefix)
    {
        size_t size = 0;
        // Check for sufficient incoming bytes
        if (bytesToValidate.size() >= 3 &&
            // If it is context-specific, allow it, else verify that it is the type we expect
            (std::byte{0} != (bytesToValidate[0] & std::byte{0x80}) || bytesToValidate[0] == static_cast<std::byte>(type)))
        {
            if (!DecodeSize(bytesToValidate.subspan(1), size, cbPrefix) || 1 + cbPrefix + size > bytesToValidate.size())
                throw std::out_of_range("Illegal size value");

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
        DecodeInner(remaining, value);
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

    DecodeResult InitSequenceOrSet()
    {
        auto isNull = false;
        // This checks internally to see if the data size is within bounds of in.size()
        if (!DecodeSequenceOrSet(DerType::ConstructedSequence, isNull))
            return DecodeResult::Failed;

        if (isNull)
            return DecodeResult::Null;

        if (0 == remaining.size())
            return DecodeResult::EmptySequence;

        return DecodeResult::Success;
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
        uint32_t i = 0;

        size = 0;

        if (remaining.size() == 0)
        {
            return false;
        }

        // Detect short form
        if ((remaining[0] & std::byte{0x80}) == std::byte{0})
        {
            size = std::to_integer<size_t>(in[0]);
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

        for (i = 1; i <= bytesToDecode; ++i)
        {
            tmp += std::to_integer<uint8_t>(remaining[i]);

            if (i < bytesToDecode)
                tmp <<= 8;
        }
        remaining = remaining.subspan(bytesToDecode + 1);

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

    template <typename T>
    bool DecodeSet(std::vector<T> &out)
    {
        size_t cbPrefix = 0;
        size_t cbSize = 0;

        if (DecodeSetOrSequenceOf(DerType::ConstructedSet, cbPrefix, cbSize, out))
        {
            remaining = remaining.subspan(cbPrefix + cbSize);
            return true;
        }

        return false;
    }

    template <typename T>
    bool DecodeSequenceOf(size_t &cbPrefix, size_t &cbSize, std::vector<T> &out)
    {
        return DecodeSetOrSequenceOf(DerType::ConstructedSequence, cbPrefix, cbSize, out);
    }

    bool IsAllUsed() const { return cbUsed == in.size(); }

    // Used to help work with optional cases
    // where we don't know that it was optional until we decode into it
    void Reset()
    {
        prefixSize = 0;
    }

private:
    std::span<const std::byte> in;
    std::span<const std::byte> remaining;
    size_t prefixSize;

    // This checks whether the tag is for a sequence, as expected, and if it is,
    // adjusts remaining.size() to only include the sequence
    bool DecodeSequenceOrSet(DerType type, bool &isNull)
    {
        // Avoid complications -
        if (DecodeNull())
        {
            isNull = true;
            return true;
        }

        isNull = false;

        // Validate the sequence
        size_t cbPrefix = 0;

        if (!CheckDecode(remaining, type, cbPrefix))
        {
            return false;
        }

        // Adjust remaining data to start at the beginning of the sequence
        remaining = remaining.subspan(cbPrefix);
        return true;
    }

    template <typename T>
    bool DecodeSetOrSequenceOf(DerType type, size_t &cbPrefix, size_t &cbSize, std::vector<T> &out)
    {
        bool isNull = false;
        
        out.clear();
        if (!DecodeSequenceOrSet(type, isNull))
        {
            cbSize = 0;
            return false;
        }

        if (isNull)
        {
            cbSize = 0;
            return true;
        }

        //offset = cbPrefix;
        //in.size() = cbPrefix + cbSize;

        while (remaining.size() > 0)
        {
            // size_t cbElement = 0;
            T t;

            // if (offset > in.size())
            //     throw std::overflow_error("Integer overflow");

            if (!t.Decode(*this))
            {
                // Accomodate the case where we have to decode into the
                // sequence to see if the element is optional
                // if (cbElement == 0)
                // {
                //     cbPrefix = 0;
                // }
                cbSize = 0;
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

private:
    static void DecodeInner(std::span<const std::byte> in, std::vector<std::byte> &value)
    {
        value = std::vector<std::byte>{in.begin(), in.end()};
    }

    static void DecodeInner(std::span<const std::byte> in, std::span<const std::byte> &value)
    {
        value = in;
    }

    template <typename CharType>
    static void DecodeInner(std::span<const std::byte> in, std::basic_string<CharType> &value)
    {
        auto pIn = reinterpret_cast<const CharType *>(in.data());
        auto stringView = std::basic_string_view<CharType>{pIn, in.size()};
        value = std::basic_string<CharType>{stringView.begin(), stringView.end()};
    }
};
