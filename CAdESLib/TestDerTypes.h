#pragma once

#include "Common.h"
//template <DerType Tag>
class TestDerType
{

public:
    TestDerType() {}
    //TestDerType(TestDerType& other): parent(std::move(other.parent)), children(std::move(other.children)) {}
    // TestDerType& operator=(const TestDerType& other) {
    //     if (this == &other)
    //         return *this;
    //     this->parent = std::move(other.parent);
    //     this->children = std::move(other.children);
    //     return *this;
    // }
    TestDerType(std::weak_ptr<TestDerType> parent) : parent(parent) {}

    static std::shared_ptr<TestDerType> Init(std::span<const std::byte> in)
    {
        auto tdtParent = std::make_shared<TestDerType>();
        TestDerType::Init(in, tdtParent);
        return tdtParent;
    }

    void Print()
    {
        Print(0);
    }

private:
    static void Init(std::span<const std::byte> in, std::shared_ptr<TestDerType> tdt)
    {
        tdt->tag = (DerType)in[0];

        // parse tag
        in = in.subspan(1);
        if (in.size() == 0)
        {
            tdt->dataLength = 0;
            return;
        }

        // parse length
        size_t size = 0;
        // Detect short form
        if ((in[0] & std::byte{0x80}) == std::byte{0})
        {
            size = std::to_integer<size_t>(in[0]);
            tdt->totalLength = 2 + size;
            tdt->dataBytes = in.subspan(1, size);
        }
        else
        {
            auto bytesToDecode = std::to_integer<size_t>(in[0] & ~std::byte{0x80});

            // Decode a maximum of 8 bytes, which adds up to a 56-bit number
            // That's MUCH bigger than anything we could possibly decode
            // And bytes to decode has to be at least one, or it isn't legal
            // Note - the case of 1 happens when you have a length between 128 and 255,
            // so the high bit is set, which precludes short form, resulting in a pattern of 0x81, 0x8b
            // to encode the value of 139.
            if (bytesToDecode > 8 || bytesToDecode >= in.size() || bytesToDecode == 0)
                throw std::overflow_error("Invalid byte length");

            for (size_t i = 1; i <= bytesToDecode; ++i)
            {
                size += std::to_integer<uint8_t>(in[i]);

                if (i < bytesToDecode)
                    size <<= 8;
            }

            // We now have the size in a 64-bit value, check whether it fits in a size_t
            // Arbitrarily say that max size is 1/2 SIZE_T_MAX
            size_t maxSize = (~(static_cast<size_t>(0))) >> 1;

            if (size > maxSize)
            {
                throw std::overflow_error("Invalid encoded size");
            }
            tdt->totalLength = bytesToDecode + size + 2; // + 2 for tag & initial length byte
            tdt->dataBytes = in.subspan(bytesToDecode + 1, size); // + 1 for the initial byte
        }

        tdt->dataLength = size;

        if (((int)tdt->tag & (int)DerType::Constructed) == (int)DerType::Constructed)
        {
            auto innerValue = tdt->dataBytes;
            while (innerValue.size() > 0)
            {
                auto childTdt = std::make_shared<TestDerType>(tdt);
                TestDerType::Init(innerValue, childTdt);
                tdt->children.push_back(childTdt);
                innerValue = innerValue.subspan(childTdt->totalLength);
            }
        }
    }
    
private:
    void Print(int level)
    {
        for (auto i = 0; i < level; i++)
        {
            std::cout << "  ";
        }
        std::cout << "Tag: 0x" << std::setfill('0') << std::setw(2) << std::hex << (int)tag
                  << " [" << std::dec << dataLength << "]" << std::endl;

        for (auto&& child: children) {
            child->Print(level + 1);
        }
    }
    std::shared_ptr<TestDerType> parent;
    std::vector<std::shared_ptr<TestDerType>> children;
    DerType tag;
    size_t totalLength;
    size_t dataLength;
    std::span<const std::byte> dataBytes;
};

// class SequenceDerType : TestDerType<DerType::ConstructedSequence>
// {
// };

// class IntegerDerType : TestDerType<DerType::Integer>
// {
// };

// class OidDerType : TestDerType<DerType::ObjectIdentifier>
// {
// };

// class Utf8StringDerType : TestDerType<DerType::UTF8String>
// {
// };

// class UtcTimeDerType : TestDerType<DerType::UTCTime>
// {
// };

// class BitStringDerType : TestDerType<DerType::BitString>
// {
// };

// class OctetStringDerType : TestDerType<DerType::OctetString>
// {
// };

// class ConstructedSetDerType : TestDerType<DerType::ConstructedSet>
// {
// };

// class NullDerType : TestDerType<DerType::Null>
// {
// };

// class BooleanDerType : TestDerType<DerType::Boolean>
// {
// };