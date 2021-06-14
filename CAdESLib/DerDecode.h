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
    template <typename T, typename Char = void, typename Traits = void>
    static bool Decode(std::span<const std::byte> in, const DerType type, T &value)
    {
        size_t cbPrefix = 0;

        if (!CheckDecode(in, type, cbPrefix))
        {
            // Allow Null, will correctly set cbData
            return DerDecode::DecodeNull(in, cbPrefix);
        }

        DecodeInner(in.subspan(cbPrefix), value);
        return true;
    }

    // Basic check for any type
    inline static bool CheckDecode(std::span<const std::byte> in, DerType type, size_t &cbPrefix)
    {
        size_t size = 0;
        // Check for sufficient incoming bytes
        if (in.size() >= 3 &&
            // If it is context-specific, allow it, else verify that it is the type we expect
            (std::byte{0} != (in[0] & std::byte{0x80}) || in[0] == static_cast<std::byte>(type)))
        {
            if (!DecodeSize(in.subspan(1), size, cbPrefix) || 1 + cbPrefix + size > in.size())
                throw std::out_of_range("Illegal size value");

            cbPrefix++;
            return true;
        }
        else if (in.size() == 2 && in[1] == std::byte{0})
        {
            // Zero length sequence, which can happen if the first member has a default, and the remaining are optional
            cbPrefix = 2;
            return true;
        }

        cbPrefix = 0;
        return false;
    }

    // Check for types that have a vector or a type of string
    inline static bool DecodeNull(std::span<const std::byte> in, size_t &cbUsed)
    {
        if (in.size() >= 2 && in[0] == static_cast<std::byte>(DerType::Null) && in[1] == std::byte{0})
        {
            cbUsed = 2;
            return true;
        }

        cbUsed = 0;
        return false;
    }

    inline static bool DecodeSize(std::span<const std::byte> in, size_t &size, size_t &cbRead)
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

public:
    DerDecode(std::span<const std::byte> in, size_t &cbUsed) 
    : in(in), remaining(in), prefixSize(0), cbUsed(cbUsed)
    {
    }

    ~DerDecode()
    {
        cbUsed += prefixSize;
    }

    DerDecode (const DerDecode &) = delete;
    DerDecode &operator=(const DerDecode &) = delete;
    DerDecode &operator=(DerDecode &&) = delete;

    DecodeResult Init()
    {
        auto isNull = false;
        // This checks internally to see if the data size is within bounds of in.size()
        if (!DecodeSequenceOrSet(DerType::ConstructedSequence, isNull))
            return DecodeResult::Failed;

        if (isNull)
            return DecodeResult::Null;

        if (cbUsed == in.size())
            return DecodeResult::EmptySequence;

        prefixSize = cbUsed;
        return DecodeResult::Success;
    }

    std::span<const std::byte> RemainingData() const { return remaining; }

    template <typename T>
    bool DecodeSet(std::vector<T> &out)
    {
        size_t cbPrefix = 0;
        size_t cbSize = 0;
        bool ret = DecodeSetOrSequenceOf(DerType::ConstructedSet, cbPrefix, cbSize, out);

        if (ret)
            cbUsed = cbPrefix + cbSize;

        return ret;
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
    size_t &cbUsed;

    // This checks whether the tag is for a sequence, as expected, and if it is,
    // adjusts remaining.size() to only include the sequence
    bool DecodeSequenceOrSet(DerType type, bool &isNull)
    {
        // Avoid complications -
        if (DecodeNull(in, cbUsed))
        {
            isNull = true;
            return true;
        }

        isNull = false;

        // Validate the sequence
        size_t cbPrefix = 0;

        if (!CheckDecode(in, type, cbPrefix))
        {
            cbUsed = 0;
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
        size_t offset = 0;

        out.clear();
        cbUsed = cbPrefix;
        if (!DecodeSequenceOrSet(type, isNull))
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
        //in.size() = cbPrefix + cbSize;

        for (;;)
        {
            size_t cbElement = 0;
            T t;

            if (offset > in.size())
                throw std::overflow_error("Integer overflow");

            if (!t.Decode(in.subspan(offset)))
            {
                // Accomodate the case where we have to decode into the
                // sequence to see if the element is optional
                if (cbElement == 0)
                {
                    cbPrefix = 0;
                    cbSize = 0;
                }
                return false;
            }

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
