#pragma once
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
	References:
	https://www.rfc-editor.org/rfc/rfc2510.txt -- Certificate Management Protocols
	https://www.rfc-editor.org/rfc/rfc2560.txt -- Online Certificate Status Protocol - OCSP

	https://www.rfc-editor.org/rfc/rfc3161.txt -- Time-Stamp Protocol (TSP)

	https://www.rfc-editor.org/rfc/rfc3279.txt -- Algorithms
	https://www.rfc-editor.org/rfc/rfc3280.txt -- Certificate and Certificate Revocation List (CRL) Profile
	https://www.rfc-editor.org/rfc/rfc3281.txt -- An Internet Attribute Certificate Profile for Authorization
	https://www.rfc-editor.org/rfc/rfc3852.txt -- Cryptographic Message Syntax (CMS)
	https://tools.ietf.org/html/rfc4055        -- Algorithm Identifiers
    https://tools.ietf.org/html/rfc4519        -- LDAP protocol, defines additional name elements that can be included in issuer or subject names

	https://www.rfc-editor.org/rfc/rfc5126.txt -- CMS Advanced Electronic Signatures (CAdES)
	https://www.rfc-editor.org/rfc/rfc5035.txt -- Enhanced Security Services (ESS) Update: Adding CertID Algorithm Agility
	https://tools.ietf.org/html/rfc5280        -- Updates 3280
	https://tools.ietf.org/html/rfc5652        -- Updates 3852
	https://datatracker.ietf.org/doc/rfc5758/  -- Updates 3279
	https://datatracker.ietf.org/doc/rfc6960/  -- Online Certificate Status Protocol - OCSP (draft), updates RFC 5912

	http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf - SHA3

	Helpful notes around the context specific types 
	// A good explanation can be found here -
	// https://cryptologie.net/article/262/what-are-x509-certificates-rfc-asn1-der/

*/

#include "Common.h"
#include "DerTypes.h"
#include "DerEncode.h"
#include "Oids.h"
#include "DerDecode.h"

typedef ObjectIdentifier ContentType;

enum class CertVersionValue
{
    v1 = 0,
    v2 = 1,
    v3 = 2,
    Unknown = 0xff
};

class EncapsulatedContentInfo final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = eContentType.EncodedSize() + eContent.EncodedSize();
        return cbData;
    }

    ContentType eContentType;
    OctetString eContent; // EXPLICIT OCTET STRING OPTIONAL
};

typedef AnyType AttributeValue;

// Make classes that wrap this, and then set the AttributeValue
// As appropriate for the attrType
class Attribute final : public DerBase
{
public:
    Attribute(std::string oid) : attrType(oid)
    {
    }

    Attribute(){};
    Attribute(const Attribute &rhs) : attrType(rhs.attrType)
    {
        attrValues.insert(attrValues.begin(), rhs.attrValues.begin(), rhs.attrValues.end());
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    void AddAttributeValue(const AttributeValue &value)
    {
        attrValues.push_back(value);
    }

    const ObjectIdentifier &GetAttrType() const { return attrType; }
    // Note: actually an array of AnyType
    const std::vector<AttributeValue> &GetAttrValues() const { return attrValues; }

private:
    virtual size_t SetDataSize() override
    {
        size_t cbNeeded = 0; // For the set byte

        // First, calculate how much is needed for the set of attrValues
        for (auto attrValue: attrValues)
        {
            cbNeeded += attrValue.EncodedSize();
        }

        cbNeeded += GetSizeBytes(cbNeeded) + 1;
        // And next, the sequence
        cbNeeded += attrType.EncodedSize();
        return (cbData = cbNeeded);
    }

    ObjectIdentifier attrType;
    std::vector<AttributeValue> attrValues;
};

// This isn't an Attribute, slightly different structure
typedef ObjectIdentifier AttributeType;

class AttributeTypeAndValue : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    std::string GetTypeLabel() const { return type.GetOidLabel(); }

    const ObjectIdentifier &GetOid() const { return type; }
    const AnyType &GetValue() const { return value; }

    bool GetValueAsString(std::string &out) const { return value.ToString(out); }
    bool GetTypeAndValue(std::string &out) const
    {
        std::string tmp;

        if (GetValueAsString(tmp))
        {
            out = GetTypeLabel();
            out += "= ";
            out += tmp;
            return true;
        }
        return false;
    }

    void SetType(std::string szOid) { type.SetValue(szOid); }
    void SetType(const ObjectIdentifier &obj) { type = obj; }

    void SetValue(const AnyType &at) { value = at; }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = type.EncodedSize() + value.EncodedSize());
    }

    AttributeType type;
    AnyType value; // Defined by the OID in type
};

class RelativeDistinguishedName final : public DerBase
{
    // Defined in https://www.ietf.org/rfc/rfc5280.txt
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSet, attrs, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};
        return decoder.DecodeSet(attrs);
    }

    // Note - this is declared as AttributeTypeAndValue, where the value could actually be anything,
    // but the RFC says that it should be a printable string.
    // Also, it says that this is a set, but only ever seen one element to the set.

    bool ToString(std::string &out) const
    {
        std::string tmp;

        for (const AttributeTypeAndValue &attr : attrs)
        {
            std::string szLabel = attr.GetTypeLabel();
            std::string s;

            attr.GetValueAsString(s);
            tmp += szLabel;
            tmp += "= ";
            tmp += s;
            tmp += ";";
        }

        if (tmp.size() > 0)
        {
            out.swap(tmp);
            return true;
        }

        return false;
    }

    const std::vector<AttributeTypeAndValue> &GetAttributeVector() const { return attrs; }

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(attrs);
        return cbData;
    }

    std::vector<AttributeTypeAndValue> attrs;
};

class RDNSequence final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        // This is a sequence of sets of AttributeTypeAndValue
        for (size_t item = 0; item < name.size(); ++item)
        {
            name[item].Encode(eh.DataPtr(out));
        }
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        // This is a sequence of sets of AttributeTypeAndValue
        for (size_t item = 0; decoder.RemainingData().size() > 0; ++item)
        {
            RelativeDistinguishedName rdn;
            if (!rdn.Decode(decoder.RemainingData()))
                return false;

            name.push_back(rdn);
            
        }

        return true;
    }

    bool ToString(std::string &out) const
    {
        std::string tmp;

        for (const RelativeDistinguishedName &rdn : name)
        {
            std::string s;
            if (rdn.ToString(s))
            {
                tmp += s;
            }
        }

        if (tmp.size() > 0)
        {
            out.swap(tmp);
            return true;
        }

        return false;
    }

    const std::vector<RelativeDistinguishedName> &GetRDNVector() const { return name; }

private:
    virtual size_t SetDataSize() override
    {
        size_t cbNeeded = 0;

        // First, calculate how much is needed for the set of names
        for (size_t i = 0; i < name.size(); ++i)
        {
            size_t cbName = name[i].EncodedSize();
            cbNeeded += cbName;
        }

        return (cbData = cbNeeded);
    }

    /*
        Name ::= CHOICE { -- only one possibility for now -- rdnSequence  RDNSequence }

        RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

        RelativeDistinguishedName ::=
            SET SIZE (1..MAX) OF AttributeTypeAndValue

        AttributeTypeAndValue ::= SEQUENCE {
            type     AttributeType,
            value    AttributeValue }
    */
    std::vector<RelativeDistinguishedName> name;
};

class Name final : public DerBase
{
public:
    // This is a CHOICE, but there is only one choice,
    // And oddly, it is a sequence that is a sequence of only one type
    virtual void Encode(std::span<std::byte> out) override
    {
        rdnSequence.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        // A Name is a CHOICE, but there's only one possible type, which is an rdnSequence
        return rdnSequence.Decode(in);
    }

    virtual size_t EncodedSize() const override
    {
        return rdnSequence.EncodedSize();
    }

    bool ToString(std::string &s) const
    {
        return rdnSequence.ToString(s);
    }

    const RDNSequence &GetRDNSequence() const { return rdnSequence; }

private:
    virtual size_t SetDataSize() override
    {
        cbData = 0;
        return cbData;
    }

    RDNSequence rdnSequence;
};

typedef Integer CertificateSerialNumber;

class IssuerAndSerialNumber final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = issuer.EncodedSize() + serialNumber.EncodedSize();
        return cbData;
    }

    Name issuer;
    CertificateSerialNumber serialNumber;
};

class SubjectKeyIdentifier;

enum class SignerIdentifierType
{
    NotSet,
    Issuer,
    SubjectKey,
    Error
};

/*
    SignerIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier }
*/

class SignerIdentifier final : public ChoiceType
{
public:
    SignerIdentifier() {}

    // Encode, Decode inherited
    SignerIdentifierType GetType() const
    {
        if (derType._class == DerClass::Universal && derType.constructed == 1 && derType.type == DerType::Sequence)
            return SignerIdentifierType::Issuer;
        else if (derType._class == DerClass::ContextSpecific && derType.constructed == 0 && derType.type == static_cast<DerType>(0))
            return SignerIdentifierType::SubjectKey;
        else
            return SignerIdentifierType::Error;
    }

private:
};

class Extension final : public DerBase
{
    /*
	   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING  }

		Note - the critical BOOLEAN may not be present,
		and if not, is evaluated as false
	*/
public:
    virtual size_t SetDataSize() override
    {
        size_t cbCritical = critical.GetValue() ? critical.EncodedSize() : 0;
        cbData = extnID.EncodedSize() + cbCritical + extnValue.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    std::string ExtensionIdLabel() const { return extnID.GetOidLabel(); }
    std::string ExtensionIdOidString() const { return extnID.GetOidString(); }
    bool IsCritical() const { return critical.GetValue(); }

    // The OctetString is really some number of sub-structures, which are defined by which extnID we have

    bool GetRawExtension(std::vector<std::byte> &out) const
    {
        const std::vector<std::byte> &extnData = extnValue.GetValue();

        if (extnData.size() > 0)
        {
            out.clear();
            out = extnData;
            return true;
        }

        return false;
    }

    size_t GetOidIndex() const { return extnID.GetOidIndex(); }

    const ObjectIdentifier &GetOid() const { return extnID; }
    const OctetString &GetExtensionValue() const { return extnValue; }

private:
    ObjectIdentifier extnID;
    Boolean critical;
    OctetString extnValue;
};

struct KeyUsageValue
{
    uint32_t digitalSignature : 1;
    uint32_t nonRepudiation : 1;
    uint32_t keyEncipherment : 1;
    uint32_t dataEncipherment : 1;
    uint32_t keyAgreement : 1;
    uint32_t keyCertSign : 1;
    uint32_t cRLSign : 1;
    uint32_t encipherOnly : 1;
    uint32_t decipherOnly : 1;
    uint32_t unused : 23;
};

class ExtensionBase : public DerBase
{
public:
    ExtensionBase(std::string oid = nullptr) : szOid(oid) {}

    using DerBase::Decode;
    using DerBase::Encode;
    void Encode(OctetString &os)
    {
        size_t cbNeeded = EncodedSize();
        std::vector<std::byte> &data = os.Resize(cbNeeded);
        DerBase::Encode(data);
    }

    bool Decode(const OctetString &os)
    {
        const std::vector<std::byte> &data = os.GetValue();
        return DerBase::Decode(std::span{data});
    }

protected:
    std::string szOid;
};

class RawExtension : public ExtensionBase
{
public:
    RawExtension(std::string oid = nullptr) : ExtensionBase(oid) {}

    virtual void Encode(std::span<std::byte> out) final
    {
        extension.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) final
    {
        return extension.Decode(in);
    }

    const AnyType &GetRawExtensionData() const { return extension; }

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = extension.SetDataSize());
    }

    AnyType extension;
};

class KeyUsage : public ExtensionBase
{
    /*
      id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

      KeyUsage ::= BIT STRING {
           digitalSignature        (0),
           nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
           keyEncipherment         (2),
           dataEncipherment        (3),
           keyAgreement            (4),
           keyCertSign             (5),
           cRLSign                 (6),
           encipherOnly            (7),
           decipherOnly            (8) }

    */

public:
    KeyUsage() : ExtensionBase(id_ce_keyUsage)
    {
        keyUsageValue = {};
    }

    virtual void Encode(std::span<std::byte> out) final
    {
        // Encode the value into a BitString
        bitString.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) final
    {
        if (!bitString.Decode(in) || !BitStringToKeyUsage())
            return false;

        return true;
    }

    const BitString &GetBitString() const { return bitString; }
    const KeyUsageValue GetKeyUsage() const { return keyUsageValue; }
    bool HasUsage() const { return (*reinterpret_cast<const int32_t *>(&keyUsageValue) == 0); }

private:
    virtual size_t SetDataSize() override
    {
        return cbData = bitString.EncodedSize();
    }

    bool IsKeyUsageNil() const
    {
        // Deal with the case where you have a bit string of value zero
        // which is 03 01 00
        const auto value = bitString.GetBits();

        if (value.size() == 1 && value[0] == std::byte{0})
            return true;

        return false;
    }

    bool BitStringToKeyUsage()
    {
        if (IsKeyUsageNil())
        {
            keyUsageValue = {0};
            return true;
        }

        auto unusedBits = bitString.UnusedBits();
        std::span<const std::byte> bits;

        if (!bitString.GetValue(bits) || bits.size() < 2)
            return false;

        // 0th byte are the count of unused bits
        // According to the standard, we can't rely on the layout of a bitfield
        // But ASN.1 does define the bit layout from left to right

        // Let's find out how many bits we actually have to set -
        size_t cBits = ((bits.size() - 1) * 8) - unusedBits;
        keyUsageValue = {0};

        constexpr auto zero = std::byte{0};
        for (size_t i = 0; i < cBits; ++i)
        {
            switch (i)
            {
            case 0:
                if (zero != (bits[1] & std::byte{0x80}))
                    keyUsageValue.digitalSignature = 1;
                break;
            case 1:
                if (zero != (bits[1] & std::byte{0x40}))
                    keyUsageValue.nonRepudiation = 1;
                break;
            case 2:
                if (zero != (bits[1] & std::byte{0x20}))
                    keyUsageValue.keyEncipherment = 1;
                break;
            case 3:
                if (zero != (bits[1] & std::byte{0x10}))
                    keyUsageValue.dataEncipherment = 1;
                break;
            case 4:
                if (zero != (bits[1] & std::byte{0x08}))
                    keyUsageValue.keyAgreement = 1;
                break;
            case 5:
                if (zero != (bits[1] & std::byte{0x04}))
                    keyUsageValue.keyCertSign = 1;
                break;
            case 6:
                if (zero != (bits[1] & std::byte{0x02}))
                    keyUsageValue.cRLSign = 1;
                break;
            case 7:
                if (zero != (bits[1] & std::byte{0x01}))
                    keyUsageValue.encipherOnly = 1;
                break;
            case 8:
                if (zero != (bits[2] & std::byte{0x80}))
                    keyUsageValue.decipherOnly = 1;
                break;
            }
        }

        return true;
    }

    void KeyUsageToBitString()
    {
        int32_t *pvalue = reinterpret_cast<int32_t *>(&keyUsageValue);
        uint8_t bitsUsed = 0;

        for (int32_t tmp = *pvalue; tmp != 0;)
        {
            if (tmp != 0)
            {
                bitsUsed++;
                tmp <<= 1;
            }
        }

        // TODO: This code needs better comments and explanation of what it's doing, might just need to move into BitString
        // How many bytes do we write out?
        auto byteCount = (uint8_t)(bitsUsed > 0 ? bitsUsed / 8 + 1 : 0);
        auto unusedBits = (uint8_t)((byteCount * 8) - bitsUsed);
        std::byte buffer[4];

        for (uint8_t i = 0; i < byteCount && i < 4; ++i)
        {
            size_t offset = sizeof(buffer) - 1 - i;
            buffer[offset] = *reinterpret_cast<std::byte *>(pvalue);
        }

        bitString.SetValue(unusedBits, std::span{buffer}.subspan(sizeof(buffer) - byteCount, byteCount));
    }

    BitString bitString;
    KeyUsageValue keyUsageValue;
};

class ExtendedKeyUsage : public ExtensionBase
{
    /*
    id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }

    ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

    KeyPurposeId ::= OBJECT IDENTIFIER

    */
public:
    ExtendedKeyUsage() : ExtensionBase(id_ce_extKeyUsage) {}

    // Also TODO - need to capture all the EKU OIDs
    // in the samples, be able to translate the most common to a friendly name
    virtual bool Decode(std::span<const std::byte> in) final
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf<ObjectIdentifier>(cbPrefix, cbSize, ekus);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    virtual void Encode(std::span<std::byte> out) final
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));
        EncodeSetOrSequenceOf(DerType::ConstructedSet, ekus, eh.DataPtr(out));
        
    }

    const std::vector<ObjectIdentifier> &GetEkus() const { return ekus; }

private:
    size_t SetDataSize() { return (cbData = GetEncodedSize(ekus)); }

    std::vector<ObjectIdentifier> ekus;
};

typedef BitString UniqueIdentifier;

class SubjectKeyIdentifier : public ExtensionBase
{
    /*
        See RFC 5280, 4.2.1.2
        This should be a sha1 hash, but other approaches are possible.

        Typical approach is:
        (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
        value of the BIT STRING subjectPublicKey (excluding the tag,
        length, and number of unused bits).
    */
public:
    SubjectKeyIdentifier() : ExtensionBase(id_ce_subjectKeyIdentifier) {}

    virtual void Encode(std::span<std::byte> out) final
    {
        keyIdentifier.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) final
    {
        return keyIdentifier.Decode(in);
    }

    const std::vector<std::byte> &GetKeyIdentifierValue() const { return keyIdentifier.GetValue(); }
    const OctetString &GetKeyIdentifer() const { return keyIdentifier; }

private:
    OctetString keyIdentifier;

    virtual size_t SetDataSize() override
    {
        return (cbData = keyIdentifier.EncodedSize());
    }
};

typedef Attribute OtherName;
enum class DirectoryStringType
{
    NotSet,
    TeletexString,
    PrintableString, // This, or a UTF8 string, is what should be used currently
    UniversalString,
    UTF8String,
    BMPString,
    Error
};

// Ignore next as likely obsolete, implement if this is incorrect
//	TeletexString teletexString;
/*
Note - from https://tools.ietf.org/html/rfc5280#section-4.1.2.6

Section (c)
TeletexString, BMPString, and UniversalString are included
for backward compatibility, and SHOULD NOT be used for
certificates for new subjects.

DirectoryString ::= CHOICE {
teletexString           TeletexString (SIZE (1..MAX)),
printableString         PrintableString (SIZE (1..MAX)),
universalString         UniversalString (SIZE (1..MAX)),
utf8String              UTF8String (SIZE (1..MAX)),
bmpString               BMPString (SIZE (1..MAX)) }

*/

class DirectoryString final : public ChoiceType
{
public:
    DirectoryString() {}

    DirectoryStringType GetType() const
    {
        if (derType._class != DerClass::Universal || derType.constructed != 0)
            return DirectoryStringType::NotSet;

#pragma warning(disable : 4061)
        switch (derType.type)
        {
        case DerType::TeletexString:
            return DirectoryStringType::TeletexString;
        case DerType::PrintableString:
            return DirectoryStringType::PrintableString;
        case DerType::UniversalString:
            return DirectoryStringType::UTF8String;
        case DerType::UTF8String:
            return DirectoryStringType::UTF8String;
        case DerType::BMPString:
            return DirectoryStringType::BMPString;
        default:
            return DirectoryStringType::Error;
        }
#pragma warning(default : 4061)
    }

private:
    // the data is encapsulated in an AnyType
};

class EDIPartyName final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    const DirectoryString &GetNameAssigner() const { return nameAssigner; }
    const DirectoryString &GetPartyName() const { return partyName; }

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = nameAssigner.EncodedSize() + partyName.EncodedSize());
    }

    DirectoryString nameAssigner;
    DirectoryString partyName;
};

enum class GeneralNameType
{
    NotSet = -1,
    OtherName = 0,                 // otherName = OtherName
    rfc822Name = 1,                // rfc822Name = IA5String
    dNSName = 2,                   // dNSName = IA5String
    x400Address = 3,               // ORAddress
    directoryName = 4,             // directoryName = Name
    ediPartyName = 5,              // ediPartyName = EDIPartyName
    uniformResourceIdentifier = 6, // uniformResourceIdentifier = IA5String
    iPAddress = 7,                 // iPAddress = OctetString
    registeredID = 8,              // registeredID = ObjectIdentifier
    Error = 9
};

/*
GeneralName ::= CHOICE {
otherName                       [0]     OtherName,
rfc822Name                      [1]     IA5String,
dNSName                         [2]     IA5String,
x400Address                     [3]     ORAddress,
directoryName                   [4]     Name,
ediPartyName                    [5]     EDIPartyName,
uniformResourceIdentifier       [6]     IA5String,
iPAddress                       [7]     OCTET STRING,
registeredID                    [8]     OBJECT IDENTIFIER }

OtherName ::= SEQUENCE {
type-id    OBJECT IDENTIFIER,
value      [0] EXPLICIT ANY DEFINED BY type-id }

EDIPartyName ::= SEQUENCE {
nameAssigner            [0]     DirectoryString OPTIONAL,
partyName               [1]     DirectoryString }

Note - ORAddress is large, looks like this - from Appendix A.1, RFC 5280

ORAddress ::= SEQUENCE {
built-in-standard-attributes BuiltInStandardAttributes,
built-in-domain-defined-attributes
BuiltInDomainDefinedAttributes OPTIONAL,
-- see also teletex-domain-defined-attributes
extension-attributes ExtensionAttributes OPTIONAL }

For now, treat it as AnyType until we know if we need it.

*/

typedef AnyType ORAddress;

class GeneralName final : public ChoiceType
{
public:
    GeneralName() {}

    bool GetOtherName(OtherName &otherName) const
    {
        return (GetType() == GeneralNameType::OtherName && DecodeInternalType(otherName));
    }

    bool GetRFC822Name(IA5String &rfc822Name) const
    {
        return (GetType() == GeneralNameType::rfc822Name && DecodeInternalType(rfc822Name));
    }

    bool GetDNSName(IA5String &dNSName) const
    {
        return (GetType() == GeneralNameType::dNSName && DecodeInternalType(dNSName));
    }

    // Note - we do not have a sample of this, untested code
    bool GetX400Address(ORAddress &x400Address) const
    {
        return (GetType() == GeneralNameType::x400Address && DecodeInternalType(x400Address));
    }

    bool GetDirectoryName(Name &directoryName) const
    {
        return (GetType() == GeneralNameType::directoryName && DecodeInternalType(directoryName, OptionType::Explicit));
    }

    // Note - we do not have a sample of this, untested code
    bool GetEDIPartyName(EDIPartyName &ediPartyName) const
    {
        return (GetType() == GeneralNameType::ediPartyName && DecodeInternalType(ediPartyName));
    }

    bool GetURI(IA5String &uniformResourceIdentifier) const
    {
        return (GetType() == GeneralNameType::uniformResourceIdentifier && DecodeInternalType(uniformResourceIdentifier));
    }

    // Note - we do not have a sample of this, untested code
    bool GetIpAddress(OctetString &iPAddress) const
    {
        return (GetType() == GeneralNameType::iPAddress && DecodeInternalType(iPAddress));
    }

    // Note - we do not have a sample of this, untested code
    bool GetRegisteredId(ObjectIdentifier &registeredID) const
    {
        return (GetType() == GeneralNameType::registeredID && DecodeInternalType(registeredID));
    }

    GeneralNameType GetType() const
    {
        if (derType._class != DerClass::ContextSpecific)
            return GeneralNameType::Error;

// Disable unused enum values warning, it adds a lot of noise here and only specific types are supported
#pragma warning(disable : 4061)
        switch (derType.type)
        {
        case DerType::EOC:
            return GeneralNameType::OtherName;
        case DerType::Boolean:
            return GeneralNameType::rfc822Name;
        case DerType::Integer:
            return GeneralNameType::dNSName;
        case DerType::BitString:
            return GeneralNameType::x400Address;
        case DerType::OctetString:
            return GeneralNameType::directoryName;
        case DerType::Null:
            return GeneralNameType::ediPartyName;
        case DerType::ObjectIdentifier:
            return GeneralNameType::uniformResourceIdentifier;
        case DerType::ObjectDescriptor:
            return GeneralNameType::iPAddress;
        case DerType::External:
            return GeneralNameType::registeredID;
        default:
            return GeneralNameType::Error;
        }
#pragma warning(default : 4061)
    }

private:
    template <typename T>
    bool DecodeInternalType(T &t, OptionType option = OptionType::Implicit) const
    {
        if (option == OptionType::Implicit)
        {
            return value.ConvertToType(t);
        }
        else if (option == OptionType::Explicit)
        {
            size_t innerSize = 0;
            std::span<const std::byte> in = ChoiceType::GetInnerBuffer(innerSize);
            return t.Decode(in);
        }
        return false;
    }
};

class GeneralNames final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        SetDataSize();
        EncodeSetOrSequenceOf(DerType::ConstructedSet, names, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf<GeneralName>(cbPrefix, cbSize, names);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<GeneralName> &GetNames() const { return names; }

protected:
    virtual size_t SetDataSize() override
    {
        cbData = GetDataSize(names);
        return cbData;
    }

    std::vector<GeneralName> names;
};

class DistributionPointName : public DerBase
{
public:
    DistributionPointName() = default;

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        fullName.Encode(eh.DataPtr(out));
        

        nameRelativeToCRLIssuer.Encode(eh.DataPtr(out));
        
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        if (!fullName.Decode(decoder.RemainingData()))
            return false;

        
        if (decoder.IsAllUsed())
            return true;

        if (!nameRelativeToCRLIssuer.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    const GeneralNames &GetFullName() const { return fullName.GetInnerType(); }
    const RelativeDistinguishedName &GetNameRelativeToCRLIssuer() const { return nameRelativeToCRLIssuer.GetInnerType(); }

    bool HasFullName() const { return fullName.HasData(); }
    bool HasNameRelativeToCRLIssuer() const { return nameRelativeToCRLIssuer.HasData(); }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = fullName.EncodedSize() + nameRelativeToCRLIssuer.EncodedSize());
    }

    ContextSpecificHolder<GeneralNames, std::byte{0xA0}, OptionType::Implicit> fullName;
    ContextSpecificHolder<RelativeDistinguishedName, std::byte{0xA1}, OptionType::Implicit> nameRelativeToCRLIssuer;
};

typedef BitString ReasonFlags;

class DistributionPoint : public DerBase
{
public:
    DistributionPoint() = default;

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        distributionPoint.Encode(eh.DataPtr(out));
        

        reasons.Encode(eh.DataPtr(out));
        

        cRLIssuer.Encode(eh.DataPtr(out));
        
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        if (!distributionPoint.Decode(decoder.RemainingData()))
            return false;

        
        if (decoder.IsAllUsed())
            return true;

        if (!reasons.Decode(decoder.RemainingData()))
            return false;

        
        if (decoder.IsAllUsed())
            return true;

        if (!cRLIssuer.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    const DistributionPointName &GetDistributionPoint() const { return distributionPoint.GetInnerType(); }
    const ReasonFlags &GetReasonFlags() const { return reasons.GetInnerType(); }
    const GeneralNames &GetCRLIssuer() const { return cRLIssuer.GetInnerType(); }

    bool HasDistributionPoint() const { return distributionPoint.HasData(); }
    bool HasReasonFlags() const { return reasons.HasData(); }
    bool HasCRLIssuer() const { return cRLIssuer.HasData(); }

private:
    virtual size_t SetDataSize()
    {
        return cbData = distributionPoint.EncodedSize() + reasons.EncodedSize() + cRLIssuer.EncodedSize();
    }

    ContextSpecificHolder<DistributionPointName, std::byte{0xA0}, OptionType::Implicit> distributionPoint;
    ContextSpecificHolder<ReasonFlags, std::byte{0xA1}, OptionType::Implicit> reasons;
    ContextSpecificHolder<GeneralNames, std::byte{0xA2}, OptionType::Implicit> cRLIssuer;
};

class CrlDistributionPoints : public ExtensionBase
{
    /*
    RFC 5280 4.2.1.13

    This is complicated
    id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }

    CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

    DistributionPoint ::= SEQUENCE {
    distributionPoint       [0]     DistributionPointName OPTIONAL,
    reasons                 [1]     ReasonFlags OPTIONAL,
    cRLIssuer               [2]     GeneralNames OPTIONAL }

    DistributionPointName ::= CHOICE {
    fullName                [0]     GeneralNames,
    nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

    ReasonFlags ::= BIT STRING {
    unused                  (0),
    keyCompromise           (1),
    cACompromise            (2),
    affiliationChanged      (3),
    superseded              (4),
    cessationOfOperation    (5),
    certificateHold         (6),
    privilegeWithdrawn      (7),
    aACompromise            (8) }
    */
public:
    CrlDistributionPoints() : ExtensionBase(id_ce_cRLDistributionPoints) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, cRLDistributionPoints, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, cRLDistributionPoints);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<DistributionPoint> &GetDistributionPoints() const { return cRLDistributionPoints; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = GetEncodedSize(cRLDistributionPoints));
    }

    std::vector<DistributionPoint> cRLDistributionPoints;
};

class IssuingDistributionPoint : public ExtensionBase
{

    /*
    RFC 5280, 5.2.5.  Issuing Distribution Point

       IssuingDistributionPoint ::= SEQUENCE {
        distributionPoint          [0] DistributionPointName OPTIONAL,
        onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
        onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
        onlySomeReasons            [3] ReasonFlags OPTIONAL,
        indirectCRL                [4] BOOLEAN DEFAULT FALSE,
        onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }

        -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
        -- and onlyContainsAttributeCerts may be set to TRUE.

*/
public:
    IssuingDistributionPoint() : ExtensionBase(id_ce_issuingDistributionPoint) {}

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        // Everything is optional, but it can't be empty.
        /*
            Conforming CRLs issuers MUST NOT issue CRLs where the DER encoding of
            the issuing distribution point extension is an empty sequence.  That
            is, if onlyContainsUserCerts, onlyContainsCACerts, indirectCRL, and
            onlyContainsAttributeCerts are all FALSE, then either the
            distributionPoint field or the onlySomeReasons field MUST be present.
        */
        distributionPoint.Decode(decoder.RemainingData());

        if (decoder.IsAllUsed())
            return true;

        onlyContainsUserCerts.Decode(decoder.RemainingData());

        if (decoder.IsAllUsed())
            return true;

        if (onlyContainsCACerts.Decode(decoder.RemainingData()))
            

        if (decoder.IsAllUsed())
            return true;

        onlySomeReasons.Decode(decoder.RemainingData());

        if (decoder.IsAllUsed())
            return true;

        indirectCRL.Decode(decoder.RemainingData());

        if (decoder.IsAllUsed())
            return true;

        onlyContainsAttributeCerts.Decode(decoder.RemainingData());
            

        return true;
    }

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        distributionPoint.Encode(eh.DataPtr(out));
        

        onlyContainsUserCerts.Encode(eh.DataPtr(out));
        

        onlyContainsCACerts.Encode(eh.DataPtr(out));
        

        onlySomeReasons.Encode(eh.DataPtr(out));
        

        indirectCRL.Encode(eh.DataPtr(out));
        

        onlyContainsAttributeCerts.Encode(eh.DataPtr(out));
        
    }

    const DistributionPointName &GetDistributionPoint() const { return distributionPoint.GetInnerType(); }
    const bool OnlyContainsUserCerts() const
    {
        if (onlyContainsUserCerts.HasData())
            return onlyContainsUserCerts.GetInnerType().GetValue();

        return false; // default
    }

    const bool OnlyContainsCACerts() const
    {
        if (onlyContainsCACerts.HasData())
            return onlyContainsCACerts.GetInnerType().GetValue();

        return false; // default
    }

    bool HasOnlySomeReasons() const { return onlySomeReasons.HasData(); }
    const ReasonFlags &OnlySomeReasons() const { return onlySomeReasons.GetInnerType(); }

    const bool IndirectCRL() const
    {
        if (indirectCRL.HasData())
            return indirectCRL.GetInnerType().GetValue();

        return false; // default
    }

    const bool OnlyContainsAttributeCerts() const
    {
        if (onlyContainsAttributeCerts.HasData())
            return onlyContainsAttributeCerts.GetInnerType().GetValue();

        return false; // default
    }

private:
    virtual size_t SetDataSize()
    {
        return cbData = distributionPoint.EncodedSize() + onlyContainsUserCerts.EncodedSize() + onlyContainsCACerts.EncodedSize() + onlySomeReasons.EncodedSize() + indirectCRL.EncodedSize() + onlyContainsAttributeCerts.EncodedSize();
    }

    ContextSpecificHolder<DistributionPointName, std::byte{0xA0}, OptionType::Implicit> distributionPoint;
    ContextSpecificHolder<Boolean, std::byte{0xA1}, OptionType::Implicit> onlyContainsUserCerts;
    ContextSpecificHolder<Boolean, std::byte{0xA2}, OptionType::Implicit> onlyContainsCACerts;
    ContextSpecificHolder<ReasonFlags, std::byte{0xA3}, OptionType::Implicit> onlySomeReasons;
    ContextSpecificHolder<Boolean, std::byte{0xA4}, OptionType::Implicit> indirectCRL;
    ContextSpecificHolder<Boolean, std::byte{0xA5}, OptionType::Implicit> onlyContainsAttributeCerts;
};
/*
-- authority key identifier OID and syntax

id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }

AuthorityKeyIdentifier ::= SEQUENCE {
keyIdentifier             [0] KeyIdentifier            OPTIONAL,
authorityCertIssuer       [1] GeneralNames             OPTIONAL,
authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
-- authorityCertIssuer and authorityCertSerialNumber MUST both
-- be present or both be absent

KeyIdentifier ::= OCTET STRING

*/

class AuthorityKeyIdentifier : public ExtensionBase
{
public:
    AuthorityKeyIdentifier() = default;

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        keyIdentifier.Encode(eh.DataPtr(out));
        

        authorityCertIssuer.Encode(eh.DataPtr(out));
        

        authorityCertSerialNumber.Encode(eh.DataPtr(out));
        
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        if (!keyIdentifier.Decode(decoder.RemainingData()))
            return false;

        
        if (decoder.IsAllUsed())
            return true;

        if (!authorityCertIssuer.Decode(decoder.RemainingData()))
            return false;

        
        if (decoder.IsAllUsed())
            return true;

        if (!authorityCertSerialNumber.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    const OctetString &GetKeyIdentifier() const { return keyIdentifier.GetInnerType(); }
    const GeneralNames &GetAuthorityCertIssuer() const { return authorityCertIssuer.GetInnerType(); }
    const CertificateSerialNumber &GetCertificateSerialNumber() const { return authorityCertSerialNumber.GetInnerType(); }

    bool HasKeyIdentifier() const { return keyIdentifier.HasData(); }
    bool HasAuthorityCertIssuer() const { return authorityCertIssuer.HasData(); }
    bool HasCertificateSerialNumber() const { return authorityCertSerialNumber.HasData(); }

private:
    virtual size_t SetDataSize()
    {
        return cbData = keyIdentifier.EncodedSize() + authorityCertIssuer.EncodedSize() + authorityCertSerialNumber.EncodedSize();
    }

    ContextSpecificHolder<OctetString, std::byte{0x80}, OptionType::Implicit> keyIdentifier;
    ContextSpecificHolder<GeneralNames, std::byte{0xA1}, OptionType::Implicit> authorityCertIssuer;
    ContextSpecificHolder<CertificateSerialNumber, std::byte{0x82}, OptionType::Implicit> authorityCertSerialNumber;
};

/*
id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }

AuthorityInfoAccessSyntax  ::=
SEQUENCE SIZE (1..MAX) OF AccessDescription

AccessDescription  ::=  SEQUENCE {
accessMethod          OBJECT IDENTIFIER,
accessLocation        GeneralName  }

Note - access methods will be one of the below

id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
*/

class AccessDescription : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        accessMethod.Encode(eh.DataPtr(out));
        

        accessLocation.Encode(eh.DataPtr(out));
        
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        if (!accessMethod.Decode(decoder.RemainingData()))
            return false;

        
        if (!accessLocation.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    const ObjectIdentifier &GetAccessMethod() const { return accessMethod; }
    const GeneralName &GetAccessLocation() const { return accessLocation; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = accessMethod.EncodedSize() + accessLocation.EncodedSize());
    }

    ObjectIdentifier accessMethod;
    GeneralName accessLocation;
};

class AuthorityInfoAccess : public ExtensionBase
{
public:
    AuthorityInfoAccess() : ExtensionBase(id_pe_authorityInfoAccess) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, accessDescriptions, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, accessDescriptions);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<AccessDescription> &GetAccessDescriptions() const { return accessDescriptions; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = GetEncodedSize(accessDescriptions));
    }

    std::vector<AccessDescription> accessDescriptions;
};

class SubjectAltName : public ExtensionBase
{
public:
    SubjectAltName() : ExtensionBase(id_ce_subjectAltName) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        names.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        return names.Decode(in);
    }

    const GeneralNames &GetNames() const { return names; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = names.EncodedSize());
    }

    GeneralNames names;
};

// The following is Microsoft-specific
/*
It decodes to this:

Foo SEQUENCE OF: tag = [UNIVERSAL 16] constructed; length = 24
Bar SEQUENCE OF: tag = [UNIVERSAL 16] constructed; length = 10
OBJECT IDENTIFIER: tag = [UNIVERSAL 6] primitive; length = 8
{ 1 3 6 1 5 5 7 3 2 }
Bar SEQUENCE OF: tag = [UNIVERSAL 16] constructed; length = 10
OBJECT IDENTIFIER: tag = [UNIVERSAL 6] primitive; length = 8
{ 1 3 6 1 5 5 7 3 1 }
Successfully decoded 26 bytes.
rec1value Foo ::=
{
bar {
{ 1 3 6 1 5 5 7 3 2 }
},
bar {
{ 1 3 6 1 5 5 7 3 1 }
}
}
*/
class KeyPurposes : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, keyPurposes, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, keyPurposes);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<ObjectIdentifier> &GetKeyPurposes() const { return keyPurposes; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = GetEncodedSize(keyPurposes));
    }

    std::vector<ObjectIdentifier> keyPurposes;
};

class ApplicationCertPolicies : public ExtensionBase
{
public:
    ApplicationCertPolicies() : ExtensionBase(id_microsoft_appCertPolicies) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, certPolicies, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, certPolicies);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<KeyPurposes> &GetCertPolicies() { return certPolicies; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = GetEncodedSize(certPolicies));
    }

    std::vector<KeyPurposes> certPolicies;
};

/*
    This is Microsoft-specific, is somewhat documented here:
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa377580(v=vs.85).aspx

    CryptDecode will expand this to:
    struct _CERT_TEMPLATE_EXT {
    LPSTR pszObjId;
    DWORD dwMajorVersion;
    BOOL  fMinorVersion;
    DWORD dwMinorVersion;
    } CERT_TEMPLATE_EXT, *PCERT_TEMPLATE_EXT;
*/
class CertTemplate : public ExtensionBase
{
public:
    CertTemplate() : ExtensionBase(id_microsoft_certTemplate) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        objId.Encode(eh.DataPtr(out));
        

        majorVersion.Encode(eh.DataPtr(out));
        

        minorVersion.Encode(eh.DataPtr(out));
        
    }

    bool Decode(std::span<const std::byte> in)
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
        case DecodeResult::EmptySequence:
            return true;
        case DecodeResult::Success:
            break;
        }

        if (!objId.Decode(decoder.RemainingData()))
            return false;

        
        if (!majorVersion.Decode(decoder.RemainingData()))
            return false;

        
        if (!minorVersion.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    const ObjectIdentifier &GetObjectIdentifier() const { return objId; }
    const Integer &GetMajorVersion() const { return majorVersion; }
    const Integer &GetMinorVersion() const { return minorVersion; }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = objId.EncodedSize() + majorVersion.EncodedSize() + minorVersion.EncodedSize());
    }

    ObjectIdentifier objId;
    Integer majorVersion;
    Integer minorVersion; // possibly optional, uncertain how this shows up
};

/*
2.5.29.1 is id_ce_authorityKeyIdentifier_old - an obsolete key identifier struct

_CERT_AUTHORITY_KEY_ID_INFO {
CRYPT_DATA_BLOB    KeyId;
CERT_NAME_BLOB     CertIssuer;
CRYPT_INTEGER_BLOB CertSerialNumber;
} CERT_AUTHORITY_KEY_ID_INFO, *PCERT_AUTHORITY_KEY_ID_INFO;

A sample of this decodes to:

30 3C
    80 10 1A1C16784CB2ADBB3193686842AA6118 - MD5 hash???
    A1 16
        30 14
            31 12
                30 10
                    06 03 550403
                    13 09 446F73436861727473 - Issuer name
    82 10 4D380E26826DB1A245496B06658683B1 -- serialNumber - Integer
*/

// Until we have the decode written for this, use RawExtension
class KeyIdentifierObsolete : public RawExtension
{
public:
    KeyIdentifierObsolete() : RawExtension(id_ce_authorityKeyIdentifier_old) {}
};

/*
id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

BasicConstraints ::= SEQUENCE {
cA                      BOOLEAN DEFAULT FALSE,
pathLenConstraint       INTEGER (0..MAX) OPTIONAL }

*/

class BasicConstraints : public ExtensionBase
{
public:
    BasicConstraints() : ExtensionBase(id_ce_basicConstraints) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeHelper eh(out);

        eh.Init(EncodedSize(), static_cast<std::byte>(DerType::ConstructedSequence));

        cA.Encode(eh.DataPtr(out));
        

        pathLenConstraint.Encode(eh.DataPtr(out));
        
    }

    bool Decode(std::span<const std::byte> in)
    {
        DerDecode decoder{in, cbData};

        switch (decoder.Init())
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
            return true;
        case DecodeResult::Success:
            break;
        case DecodeResult::EmptySequence:
            (cA.GetInnerType()).SetValue(false);
            return true;
        }

        if (cA.IsPresent(decoder.RemainingData()[0]))
        {
            if (!cA.Decode(decoder.RemainingData()))
                return false;

            
            if (decoder.IsAllUsed())
                return true;
        }
        else
        {
            // Default to false
            (cA.GetInnerType()).SetValue(false);
        }

        if (!pathLenConstraint.Decode(decoder.RemainingData()))
            return false;

        return true;
    }

    bool GetIsCA() const { return cA.GetInnerType().GetValue(); }
    bool HasPathLength() const { return pathLenConstraint.HasData(); }

    const Integer &GetPathLengthConstraint() const { return pathLenConstraint.GetInnerType(); }

private:
    virtual size_t SetDataSize()
    {
        return (cbData = cA.EncodedSize() + pathLenConstraint.EncodedSize());
    }

    ContextSpecificHolder<Boolean, std::byte{0x01}, OptionType::Implicit> cA;
    ContextSpecificHolder<Integer, std::byte{0x02}, OptionType::Implicit> pathLenConstraint;
};

// See comments at definition of id_google_certTransparancy
// Not well defined, draft RFC, enough for now to know it is present
class GoogleCertTransparency : public RawExtension
{
public:
    GoogleCertTransparency() : RawExtension(id_google_certTransparancy) {}
};

/*

This is documented as:

smimeCapabilities OBJECT IDENTIFIER ::= {iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 15}

SMIMECapability ::= SEQUENCE {
capabilityID OBJECT IDENTIFIER,
parameters ANY DEFINED BY capabilityID OPTIONAL }

SMIMECapabilities ::= SEQUENCE OF SMIMECapability

A sample looks like the following:

30 35
30 0E
06 08 2A864886F70D0302
02 02 0080
30 0E
06 08 2A864886F70D0304
02 02 0080
30 07
06 05 2B0E030207
30 0A
06 08 2A864886F70D0307

*/
class SmimeCapabilities : public RawExtension
{
public:
    SmimeCapabilities() : RawExtension(id_smimeCapabilities) {}
};

/*
    This is the CA version
*/
class MicrosoftCAVersion : public ExtensionBase
{
public:
    MicrosoftCAVersion() : ExtensionBase(id_microsoft_certsrvCAVersion) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        version.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return version.Decode(in);
    }

    const Integer &GetVersion() const { return version; }

private:
    virtual size_t SetDataSize() { return (cbData = version.EncodedSize()); }
    Integer version;
};

/*
    This is the enroll certificate type extension, it is a BMP string
    Sample looks like this 1E 04 00430041 ("CA")
*/

class MicrosoftEnrollCertType : public ExtensionBase
{
public:
    MicrosoftEnrollCertType() : ExtensionBase(id_microsoft_enrollCertType) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        certType.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return certType.Decode(in);
    }

    const BMPString &GetCertType() const { return certType; }

private:
    virtual size_t SetDataSize() { return (cbData = certType.EncodedSize()); }
    BMPString certType;
};

class MicrosoftCertFriendlyName : public RawExtension
{
    // Note - this is very rare, and is just a wchar_t string - not ASN.1
    // Could fairly easily decode/encode, but don't see a need to create these
    MicrosoftCertFriendlyName() : RawExtension(id_microsoft_certFriendlyName) {}
};

// Contains the sha1 hash of the previous version of the CA certificate

class MicrosoftPreviousCertHash : public ExtensionBase
{
public:
    MicrosoftPreviousCertHash() : ExtensionBase(id_microsoft_certsrvPrevHash) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        prevCertHash.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return prevCertHash.Decode(in);
    }

    const OctetString &GetPrevCertHash() const { return prevCertHash; }

private:
    virtual size_t SetDataSize() { return (cbData = prevCertHash.EncodedSize()); }
    OctetString prevCertHash;
};

/*
 Apple-specific extension, apparently carries no data
*/
class ApplePushDev : public ExtensionBase
{
public:
    ApplePushDev() : ExtensionBase(id_apple_pushDev) {}
    virtual void Encode(std::span<std::byte> out) override
    {
        nothing.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return nothing.Decode(in);
    }

private:
    virtual size_t SetDataSize() { return (cbData = nothing.EncodedSize()); }
    Null nothing;
};

/*
Apple-specific extension, apparently carries no data
*/
class ApplePushProd : public ExtensionBase
{
public:
    ApplePushProd() : ExtensionBase(id_apple_pushProd) {}
    virtual void Encode(std::span<std::byte> out) override
    {
        nothing.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return nothing.Decode(in);
    }

private:
    virtual size_t SetDataSize() { return (cbData = nothing.EncodedSize()); }
    Null nothing;
};

/*
Apple-specific extension, apparently carries no data
Unknown why this is there, cannot find documentation, seems to occur with the two above
*/
class AppleCustom6 : public ExtensionBase
{
public:
    AppleCustom6() : ExtensionBase(id_apple_custom6) {}
    virtual void Encode(std::span<std::byte> out) override
    {
        nothing.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return nothing.Decode(in);
    }

private:
    virtual size_t SetDataSize() { return (cbData = nothing.EncodedSize()); }
    Null nothing;
};

/*
    This is reasonably simple, but it is unusual, and we probably just need to know if it is there.
    It decodes to:

    30 0A
    1B 04 56342E30 (GeneralString, decodes to "v4.0")
    03 02 0490 (BitString, decodes to 9, unknown meaning)
*/
class EntrustVersion : public RawExtension
{
public:
    EntrustVersion() : RawExtension(id_entrustVersInfo) {}
};

class NetscapeCertExt : public RawExtension
{
public:
    NetscapeCertExt() : RawExtension(id_netscape_certExt) {}
};

/*
    Very rare, seems to only have issuer email and web address
*/
class IssuerAltNames : public ExtensionBase
{
public:
    IssuerAltNames() : ExtensionBase(id_ce_issuerAltName) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        altNames.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return altNames.Decode(in);
    }

    virtual size_t SetDataSize() { return (cbData = altNames.EncodedSize()); }

    const GeneralNames &GetAltNames() const { return altNames; }

private:
    GeneralNames altNames;
};

/*
    Only have one of these on an Entrust cert from 1999
    Contains a bit string with a value of 0x07, unknown meaning
*/
class NetscapeCertUnknown : public RawExtension
{
public:
    NetscapeCertUnknown() : RawExtension(id_netscape_certExt) {}
};

/*

privateKeyUsagePeriod has been deprecated, but now is not recommended:

This specification obsoletes [RFC3280].  Differences from RFC 3280
are summarized below:

[...]
* Section 4.2.1.4 in RFC 3280, which specified the
privateKeyUsagePeriod certificate extension but deprecated its
use, was removed.  Use of this ISO standard extension is neither
deprecated nor recommended for use in the Internet PKI.

Note - this structure is defined as:

PrivateKeyUsagePeriod ::= SEQUENCE {
notBefore       [0]     GeneralizedTime OPTIONAL,
notAfter        [1]     GeneralizedTime OPTIONAL }
-- either notBefore or notAfter MUST be present

It could be easily implemented once we have some way to manage OPTIONAL items,
which are polymorphic. For now, leave it alone, only have one sample on an old Entrust root
*/
class PrivateKeyUsagePeriod : public RawExtension
{
public:
    PrivateKeyUsagePeriod() : RawExtension(id_ce_privateKeyUsagePeriod) {}
};

/*
    keyUsageRestriction
    Very rarely seen, documented here - https://datatracker.ietf.org/doc/html/draft-ietf-pkix-ipki-part1-01.txt#section-4.2.5

    keyUsageRestriction  ::=  SEQUENCE  {
    certPolicySet            SEQUENCE OF CertPolicyId OPTIONAL,
    restrictedKeyUsage       KeyUsage OPTIONAL  }

    Sample:
    30 14
      30 0E
        30 0C
          06 0A 2B060104018237020116 (1.3.6.1.4.1.311.2.1.22, SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID - Microsoft specific)
      03 02 0780 (one bit, digitalSignature)

    For now, not parsing these, don't think any modern cert parser is going to enforce this
*/

class KeyUsageRestriction : public RawExtension
{
public:
    KeyUsageRestriction() : RawExtension(id_ce_keyUsageRestriction) {}
};

/*
4.2.1.15.  Freshest CRL (a.k.a. Delta CRL Distribution Point)

The freshest CRL extension identifies how delta CRL information is
obtained.  The extension MUST be marked as non-critical by conforming
CAs.  Further discussion of CRL management is contained in Section 5.

The same syntax is used for this extension and the
cRLDistributionPoints extension, and is described in Section
4.2.1.13.  The same conventions apply to both extensions.

id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }

FreshestCRL ::= CRLDistributionPoints

*/

class FreshestCRL : public ExtensionBase
{
public:
    FreshestCRL() : ExtensionBase(id_ce_freshestCRL) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        crlDist.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        return crlDist.Decode(in);
    }

    const CrlDistributionPoints &GetDistributionPoints() const { return crlDist; }

private:
    virtual size_t SetDataSize() { return (cbData = crlDist.EncodedSize()); }

    CrlDistributionPoints crlDist;
};

enum class HashAlgorithm
{
    MD2 = 0,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512
};

class AlgorithmIdentifier final : public DerBase
{
public:
    AlgorithmIdentifier(HashAlgorithm alg);

    AlgorithmIdentifier(std::string oid) : algorithm(oid)
    {
        parameters.SetNull();
    }

    AlgorithmIdentifier() = default;

    virtual size_t SetDataSize() override
    {
        cbData = algorithm.EncodedSize() + parameters.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    // Accessors
    std::string AlgorithmOid() const { return algorithm.GetOidString(); }
    std::string AlgorithmLabel() const { return algorithm.GetOidLabel(); }

    const ObjectIdentifier &GetAlgorithm() const { return algorithm; }
    const AnyType &GetParameters() const { return parameters; }

private:
    ObjectIdentifier algorithm;
    AnyType parameters; // DEFINED BY algorithm OPTIONAL
};

typedef std::vector<Attribute> SignedAttributes;
typedef std::vector<Attribute> UnsignedAttributes;
typedef OctetString SignatureValue;
typedef Integer CMSVersion;
typedef AlgorithmIdentifier DigestAlgorithmIdentifier;
typedef AlgorithmIdentifier SignatureAlgorithmIdentifier;

class SignerInfo final : public DerBase
{
public:
    SignerInfo() = default;

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (
            cbData =
                version.EncodedSize() +
                sid.EncodedSize() +
                digestAlgorithm.EncodedSize() +
                GetEncodedSize(signedAttrs) +
                signatureAlgorithm.EncodedSize() +
                signature.EncodedSize() +
                GetEncodedSize(unsignedAttrs));
    }

    CMSVersion version;
    SignerIdentifier sid;
    DigestAlgorithmIdentifier digestAlgorithm;
    SignedAttributes signedAttrs; // implicit, optional, std::vector<Attribute>
    SignatureAlgorithmIdentifier signatureAlgorithm;
    SignatureValue signature;
    UnsignedAttributes unsignedAttrs; // implicit, optional
};

class OtherCertificateFormat final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = otherCertFormat.EncodedSize() + otherCert.EncodedSize());
    }

    ObjectIdentifier otherCertFormat;
    AnyType otherCert; // DEFINED BY otherCertFormat
};

class SubjectPublicKeyInfo final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = algorithm.EncodedSize() + subjectPublicKey.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    const AlgorithmIdentifier &GetAlgorithm() const { return algorithm; }
    const BitString &GetSubjectPublicKey() const { return subjectPublicKey; }

private:
    AlgorithmIdentifier algorithm;
    BitString subjectPublicKey;
};

class Extensions final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = 0;
        for (size_t i = 0; i < values.size(); ++i)
        {
            cbData += values[i].EncodedSize();
        }
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, values, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        // This is actually a SEQUENCE, oddly, seems it should be a set
        // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, values);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    size_t Count() const { return values.size(); }
    const Extension &GetExtension(size_t index) const
    {
        if (index < values.size())
        {
            return values[index];
        }

        throw std::out_of_range("Incorrect index");
    }

private:
    std::vector<Extension> values;
};

class ExtensionData
{
public:
    ExtensionData(const std::vector<Extension> &ext) : extensions(ext) {}
    ExtensionData(const ExtensionData &) = delete;
    ExtensionData &operator=(ExtensionData &&) = delete;
    ExtensionData &operator=(const ExtensionData &) = delete;

    void LoadExtensions()
    {
        bool hasKeyUsage = false;

        for (const Extension &ext : extensions)
        {
            size_t oidIndex = ext.GetOidIndex();
            std::string oidString = oidIndex == ~static_cast<size_t>(0) ? nullptr : GetOidString(oidIndex);
            // Get the raw data from inside the OctetString
            std::vector<std::byte> extensionData;

            // TODO: handle corruptions
            if (!ext.GetRawExtension(extensionData))
            {
                // Corrupted
                continue;
            }

            // Unknown extension
            if (oidString.empty())
            {
                // do something
                continue;
            }

            if (oidString == id_ce_keyUsage)
            {
                KeyUsage keyUsage;

                if (!keyUsage.Decode(extensionData))
                    throw std::exception();

                keyUsageValue = keyUsage.GetKeyUsage();
                hasKeyUsage = true;
                continue;
            }

            if (oidString == id_ce_extKeyUsage)
            {
                ExtendedKeyUsage eku;

                if (!eku.Decode(extensionData))
                    throw std::exception();

                ekus = eku.GetEkus();
                continue;
            }

            if (oidString == id_ce_subjectKeyIdentifier)
            {
                SubjectKeyIdentifier ski;

                if (!ski.Decode(extensionData))
                    throw std::exception();

                subjectKeyIdentifier = ski.GetKeyIdentifierValue();
                continue;
            }

            if (oidString == id_ce_authorityKeyIdentifier)
            {
            }
        }

        if (!hasKeyUsage)
        {
            // Special case - if there is no key usage, all bits set
            std::memset(&keyUsageValue, 0xff, sizeof(keyUsageValue));
        }
    }

private:
    KeyUsageValue keyUsageValue;
    std::vector<ObjectIdentifier> ekus;
    std::vector<std::byte> subjectKeyIdentifier;

    const std::vector<Extension> &extensions;
};

class Validity final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    const Time &GetNotBefore() const { return notBefore; }
    const Time &GetNotAfter() const { return notAfter; }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = notBefore.EncodedSize() + notAfter.EncodedSize());
    }

    Time notBefore;
    Time notAfter;
};

class TBSCertificate final : public DerBase
{
public:
    // These fields are context-specific, and may not be present (not just null)
    TBSCertificate() = default;

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    // Accessors
    // version
    uint32_t GetVersion() const
    {
        const Integer &_version = version.GetInnerType();
        uint32_t l = 0;

        if (_version.GetValue(l) && l < 3)
        {
            // Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
            return l + 1;
        }
        else
        {
            return static_cast<uint32_t>(0);
        }
    }

    std::string GetVersionString() const
    {
        switch (GetVersion())
        {
        case 0:
            return "v1";
        case 1:
            return "v2";
        case 2:
            return "v3";
        default:
            return "Unknown version";
            break;
        }
    }

    // serialNumber
    // TBD, consider conversion to string as decimal or hexadecimal
    void GetSerialNumber(std::span<const std::byte> &out) const
    {
        out = serialNumber.GetBytes();
    }

    // signature
    std::string SignatureAlgorithm() const { return signature.AlgorithmLabel(); }
    std::string SignatureAlgorithmOid() const { return signature.AlgorithmOid(); }

    // issuer
    bool GetIssuer(std::string &out) const { return issuer.ToString(out); }

    // validity
    bool GetNotBefore(std::string &out) const
    {
        const Time &t = validity.GetNotBefore();
        return t.ToString(out);
    }

    bool GetNotAfter(std::string &out) const
    {
        const Time &t = validity.GetNotAfter();
        return t.ToString(out);
    }

    // subject
    bool GetSubject(std::string &out) const { return subject.ToString(out); }

    // subjectPublicKeyInfo
    std::string PublicKeyAlgorithm() const
    {
        const AlgorithmIdentifier &alg = subjectPublicKeyInfo.GetAlgorithm();
        return alg.AlgorithmLabel();
    }

    std::string PublicKeyOid() const
    {
        const AlgorithmIdentifier &alg = subjectPublicKeyInfo.GetAlgorithm();
        return alg.AlgorithmOid();
    }

    void GetPublicKey(uint8_t &unusedBits, std::vector<std::byte> &out)
    {
        const BitString &bits = subjectPublicKeyInfo.GetSubjectPublicKey();
        bits.GetValue(unusedBits, out);
    }

    // issuerUniqueID
    bool GetIssuerUniqueID(uint8_t &unusedBits, std::vector<std::byte> &out)
    {
        const BitString &bits = issuerUniqueID.GetInnerType();

        if (bits.ValueSize() > 0)
        {
            bits.GetValue(unusedBits, out);
            return true;
        }

        return false;
    }

    // subjectUniqueID
    bool GetSubjectUniqueID(uint8_t &unusedBits, std::vector<std::byte> &out)
    {
        const BitString &bits = subjectUniqueID.GetInnerType();

        if (bits.ValueSize() > 0)
        {
            bits.GetValue(unusedBits, out);
            return true;
        }

        return false;
    }

    // extensions
    size_t GetExtensionCount() const { return (extensions.GetInnerType()).Count(); }
    const Extension &GetExtension(size_t index) const { return (extensions.GetInnerType()).GetExtension(index); }
    // Accessors for translation to XML (or other output)
    const Integer &GetVersionAsInteger() const { return version.GetInnerType(); }
    const Integer &GetSerialNumber() const { return serialNumber; }
    const AlgorithmIdentifier &GetSignature() const { return signature; }
    const Name &GetIssuer() const { return issuer; }
    const Validity &GetValidity() const { return validity; }
    const Name &GetSubject() const { return subject; }
    const SubjectPublicKeyInfo &GetSubjectPublicKeyInfo() const { return subjectPublicKeyInfo; }

    bool HasIssuerId() const { return issuerUniqueID.HasData(); }
    bool HasSubjectId() const { return subjectUniqueID.HasData(); }
    const UniqueIdentifier &GetIssuerId() const { return issuerUniqueID.GetInnerType(); }
    const UniqueIdentifier &GetSubjectId() const { return subjectUniqueID.GetInnerType(); }

    const Extensions &GetExtensions() const { return extensions.GetInnerType(); }

private:
    virtual size_t SetDataSize() override
    {
        // To facilitate debugging
        size_t cbVersion = version.EncodedSize();
        size_t cbSerial = serialNumber.EncodedSize();
        size_t cbSignature = signature.EncodedSize();
        size_t cbIssuer = issuer.EncodedSize();
        size_t cbValidity = validity.EncodedSize();
        size_t cbSubject = subject.EncodedSize();
        size_t cbPublicKey = subjectPublicKeyInfo.EncodedSize();
        size_t cbIssuerId = issuerUniqueID.EncodedSize();
        size_t cbSubjectId = subjectUniqueID.EncodedSize();
        size_t cbExtensions = extensions.EncodedSize();

        cbData =
            cbVersion +
            cbSerial +
            cbSignature +
            cbIssuer +
            cbValidity +
            cbSubject +
            cbPublicKey +
            cbIssuerId +
            cbSubjectId +
            cbExtensions;

        return cbData;
    }

    ContextSpecificHolder<Integer, std::byte{0xA0}, OptionType::Explicit> version;
    CertificateSerialNumber serialNumber;
    AlgorithmIdentifier signature;
    Name issuer;
    Validity validity;
    Name subject;
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    // Note - optional fields may be missing, not have null placeholders
    ContextSpecificHolder<UniqueIdentifier, std::byte{0x81}, OptionType::Implicit> issuerUniqueID;  // optional
    ContextSpecificHolder<UniqueIdentifier, std::byte{0x82}, OptionType::Implicit> subjectUniqueID; // optional
    ContextSpecificHolder<Extensions, std::byte{0xA3}, OptionType::Explicit> extensions;            // optional, will have value 0xA3
};

class Certificate final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    // Accessors
    // signatureValue
    size_t SignatureSize() const { return signatureValue.ValueSize(); }
    bool GetSignatureValue(uint8_t &unusedBits, std::vector<std::byte> &out) const { return signatureValue.GetValue(unusedBits, out); }

    // signatureAlgorithm
    // TBD - create a way to return parameters if they are ever not null
    std::string SignatureAlgorithmLabel() const
    {
        std::string szLabel = signatureAlgorithm.AlgorithmLabel();
        return !szLabel.empty() ? szLabel : signatureAlgorithm.AlgorithmOid();
    }

    const AlgorithmIdentifier &GetSignatureAlgorithm() const { return signatureAlgorithm; }
    const BitString &GetSignatureValue() const { return signatureValue; }
    const TBSCertificate &GetTBSCertificate() const { return tbsCertificate; }

    const std::string &GetFileName() const { return fileName; }
    void SetFileName(const std::string &name) { fileName = name; }

    const std::vector<std::byte> &GetThumbprint() const { return thumbprint; }
    std::vector<std::byte> &GetThumbprint() { return thumbprint; }

    const std::vector<std::byte> &GetThumbprint256() const { return thumbprint256; }
    std::vector<std::byte> &GetThumbprint256() { return thumbprint256; }

private:
    virtual size_t SetDataSize() override
    {
        cbData = tbsCertificate.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize();
        return cbData;
    }

    TBSCertificate tbsCertificate;
    AlgorithmIdentifier signatureAlgorithm;
    BitString signatureValue;
    std::string fileName;
    std::vector<std::byte> thumbprint;
    std::vector<std::byte> thumbprint256;
};

enum class DigestedObjectTypeValue
{
    publicKey = 0,
    publicKeyCert = 1,
    otherObjectTypes = 2
};

class DigestedObjectType : public Enumerated
{
public:
    DigestedObjectType(DigestedObjectTypeValue v = DigestedObjectTypeValue::publicKey) : Enumerated(static_cast<std::byte>(v)) {}
};

class IssuerSerial final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = issuer.EncodedSize() + serial.EncodedSize() + issuerUID.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    GeneralNames issuer;
    CertificateSerialNumber serial;
    UniqueIdentifier issuerUID;
};

class ObjectDigestInfo final : public DerBase
{
public:
    ObjectDigestInfo() {}

    virtual size_t SetDataSize() override
    {
        cbData =
            digestedObjectType.EncodedSize() +
            otherObjectTypeID.EncodedSize() +
            digestAlgorithm.EncodedSize() +
            objectDigest.EncodedSize();

        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    DigestedObjectType digestedObjectType;
    ObjectIdentifier otherObjectTypeID;
    AlgorithmIdentifier digestAlgorithm;
    BitString objectDigest;
};

class Holder final : public DerBase
{
public:
    Holder() {}

    virtual size_t SetDataSize() override
    {
        cbData = baseCertificateID.EncodedSize() + entityName.EncodedSize() + objectDigestInfo.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    IssuerSerial baseCertificateID; // optional
    GeneralNames entityName;
    ObjectDigestInfo objectDigestInfo;
};

class AttCertValidityPeriod final : public DerBase
{
public:
    virtual size_t SetDataSize() override { return (cbData = notBeforeTime.EncodedSize() + notAfterTime.EncodedSize()); }
    virtual void Encode(std::span<std::byte> out) override;

    virtual bool Decode(std::span<const std::byte> in) override;

    GeneralizedTime notBeforeTime;
    GeneralizedTime notAfterTime;
};

class V2Form final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = issuerName.EncodedSize() + baseCertificateID.EncodedSize() + objectDigestInfo.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    GeneralNames issuerName;
    IssuerSerial baseCertificateID;
    ObjectDigestInfo objectDigestInfo;
};

// AttCertIssuer is defined as a union, but
// GeneralNames v1Form must not be used, so typedef
typedef V2Form AttCertIssuer;
typedef Integer AttCertVersion;

class AttributeCertificateInfo final : public DerBase
{
public:
    AttributeCertificateInfo()
    {
    }

    virtual size_t SetDataSize() override
    {
        cbData =
            version.EncodedSize() +
            holder.EncodedSize() +
            issuer.EncodedSize() +
            signature.EncodedSize() +
            serialNumber.EncodedSize() +
            attrCertValidityPeriod.EncodedSize() +
            issuerUniqueID.EncodedSize() +
            GetEncodedSize(attributes) +
            extensions.EncodedSize();

        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    AttCertVersion version; // set this to CertVersionValue::v2
    Holder holder;
    AttCertIssuer issuer;
    AlgorithmIdentifier signature;
    CertificateSerialNumber serialNumber;
    AttCertValidityPeriod attrCertValidityPeriod;
    std::vector<Attribute> attributes;
    UniqueIdentifier issuerUniqueID; // optional
    Extensions extensions;           // optional
};

class AttributeCertificate final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        return (cbData = acinfo.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize());
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    AttributeCertificateInfo acinfo;
    AlgorithmIdentifier signatureAlgorithm;
    BitString signatureValue;
};

typedef AttributeCertificate AttributeCertificateV2;

enum class CertificateChoicesType
{
    NotSet,
    Cert,
    AttributeCert,
    OtherCert
};

/*
CertificateChoices ::= CHOICE {
    certificate Certificate,
    extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
    v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
    v2AttrCert [2] IMPLICIT AttributeCertificateV2,
    other [3] IMPLICIT OtherCertificateFormat }

OtherCertificateFormat ::= SEQUENCE {
    otherCertFormat OBJECT IDENTIFIER,
    otherCert ANY DEFINED BY otherCertFormat }

*/
class CertificateChoices final : public DerBase
{
public:
    CertificateChoices(CertificateChoicesType t = CertificateChoicesType::NotSet) : type(t) {}

    void SetValue(Certificate &certificate) { SetValue(CertificateChoicesType::Cert, certificate); }
    void SetValue(AttributeCertificateV2 &v2AttrCert) { SetValue(CertificateChoicesType::AttributeCert, v2AttrCert); }
    void SetValue(OtherCertificateFormat &other) { SetValue(CertificateChoicesType::OtherCert, other); }

    virtual void Encode(std::span<std::byte> out) override
    {
        value.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        return value.Decode(in);
    }

    AnyType value;

protected:
    virtual size_t SetDataSize() override
    {
        return value.SetDataSize();
    }

private:
    template <typename T>
    void SetValue(CertificateChoicesType t, T &in)
    {
        type = t;
        value.SetValue(in);
    }

    CertificateChoicesType type;
};

typedef Extensions CrlExtensions;

class RevocationEntry final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    CertificateSerialNumber userCertificate;
    Time revocationDate;
    Extensions crlEntryExtensions; // optional

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = userCertificate.EncodedSize() + revocationDate.EncodedSize() + crlEntryExtensions.EncodedSize());
    }
};

class RevokedCertificates final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, entries, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbPrefix = 0;
        size_t cbSize = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, entries);

        if (ret)
        {
            cbData = cbSize;
            // //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    size_t GetCount() const { return entries.size(); }
    const RevocationEntry &GetRevocationEntry(size_t index) const { return entries[index]; }

protected:
    virtual size_t SetDataSize() override
    {
        cbData = 0;
        for (size_t i = 0; i < entries.size(); ++i)
        {
            cbData += entries[i].EncodedSize();
        }

        return cbData;
    }

    std::vector<RevocationEntry> entries;
};

class TBSCertList final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData =
            version.EncodedSize() +
            signature.EncodedSize() +
            issuer.EncodedSize() +
            thisUpdate.EncodedSize() +
            nextUpdate.EncodedSize() +
            revokedCertificates.EncodedSize() +
            crlExtensions.EncodedSize();

        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    Integer version; // optional, must be v2 if present
    AlgorithmIdentifier signature;
    Name issuer;
    Time thisUpdate;
    Time nextUpdate; // optional
    RevokedCertificates revokedCertificates;
    ContextSpecificHolder<CrlExtensions, std::byte{0xA0}, OptionType::Explicit> crlExtensions;
};

class CertificateList final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = tbsCertList.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    TBSCertList tbsCertList;
    AlgorithmIdentifier signatureAlgorithm;
    BitString signatureValue;
};

class OtherRevocationInfoFormat final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    ObjectIdentifier otherRevInfoFormat;
    AnyType otherRevInfo;

    virtual size_t SetDataSize() override
    {
        return (cbData = otherRevInfoFormat.EncodedSize() + otherRevInfo.EncodedSize());
    }
};

enum class RevocationInfoChoiceType
{
    NotSet,
    CRL,
    Other
};

class RevocationInfoChoice final : public DerBase
{
public:
    RevocationInfoChoice(RevocationInfoChoiceType t = RevocationInfoChoiceType::NotSet) : type(t) {}

    void SetValue(CertificateList &crl) { SetValue(RevocationInfoChoiceType::CRL, crl); }
    void SetValue(OtherRevocationInfoFormat &other) { SetValue(RevocationInfoChoiceType::Other, other); }

    virtual void Encode(std::span<std::byte> out) override
    {
        value.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        return value.Decode(in);
    }

    AnyType value;

protected:
    virtual size_t SetDataSize() override
    {
        return cbData = value.SetDataSize();
    }

private:
    template <typename T>
    void SetValue(RevocationInfoChoiceType t, T &in)
    {
        type = t;
        value.SetValue(in);
    }

    RevocationInfoChoiceType type;
};

typedef std::vector<DigestAlgorithmIdentifier> DigestAlgorithmIdentifiers;
typedef std::vector<SignerInfo> SignerInfos;
typedef std::vector<CertificateChoices> CertificateSet;
typedef std::vector<RevocationInfoChoice> RevocationInfoChoices;

class SignedData final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (
            cbData = version.EncodedSize() +
                     GetEncodedSize(digestAlgorithms) +
                     encapContentInfo.EncodedSize() +
                     GetEncodedSize(certificates) +
                     GetEncodedSize(crls) +
                     GetEncodedSize(signerInfos));
    }

    CMSVersion version;
    DigestAlgorithmIdentifiers digestAlgorithms;
    EncapsulatedContentInfo encapContentInfo;
    CertificateSet certificates; //implicit, optional
    RevocationInfoChoices crls;  //implicit, optional
    SignerInfos signerInfos;
};

class ContentInfo final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = contentType.EncodedSize() + content.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    ContentType contentType;
    AnyType content;
};

/* begin CAdES elements */
typedef OctetString Hash;
typedef ObjectIdentifier CertPolicyId;
typedef ObjectIdentifier PolicyQualifierId;
typedef IA5String CPSuri;

enum class DisplayTextType
{
    NotSet,
    Visible,
    BMP,
    UTF8
};

class DisplayText final : public DerBase
{
public:
    DisplayText(DisplayTextType t = DisplayTextType::NotSet) : type(t) {}

    void SetValue(VisibleString &visibleString) { SetValue(DisplayTextType::Visible, visibleString); }
    void SetValue(BMPString &bmpString) { SetValue(DisplayTextType::BMP, bmpString); }
    void SetValue(UTF8String &utf8String) { SetValue(DisplayTextType::UTF8, utf8String); }

    virtual size_t SetDataSize() override
    {
        cbData = value.EncodedSize();
        return cbData;
    }

    void Encode(std::span<std::byte> out)
    {
        value.Encode(out);
    }

    virtual bool Decode(std::span<const std::byte> in) override;

    AnyType value;

private:
    template <typename T>
    void SetValue(DisplayTextType t, T &in)
    {
        type = t;
        value.SetValue(in);
    }

    DisplayTextType type;
};

class NoticeReference final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(noticeNumbers) + organization.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;

    virtual bool Decode(std::span<const std::byte> in) override;

    DisplayText organization;
    std::vector<Integer> noticeNumbers;
};

class UserNotice final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = noticeRef.EncodedSize() + explicitText.EncodedSize());
    }

    NoticeReference noticeRef;
    DisplayText explicitText;
};

class PolicyQualifierInfo final : public DerBase
{
public:
    // policyQualifierId must be id-qt-cps | id-qt-unotice
    // If policyQualifierId is id-qt-cps, then qualifier is CPSuri
    // See https://tools.ietf.org/html/rfc3280 for specification

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    const PolicyQualifierId &GetPolicyQualifierId() const { return policyQualifierId; }
    const AnyType &GetQualifier() const { return qualifier; }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = policyQualifierId.EncodedSize() + qualifier.EncodedSize());
    }

    PolicyQualifierId policyQualifierId;
    AnyType qualifier;
};

class PolicyInformation final : public DerBase
{
public:
    PolicyInformation() = default;

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    const CertPolicyId &GetPolicyIdentifier() const { return policyIdentifier; }
    const std::vector<PolicyQualifierInfo> &GetPolicyQualifiers() const { return policyQualifiers; }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = policyIdentifier.EncodedSize() + GetEncodedSize(policyQualifiers));
    }

    CertPolicyId policyIdentifier;
    std::vector<PolicyQualifierInfo> policyQualifiers; // optional
};

/*
    id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }

    anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificate-policies 0 }

    certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

    PolicyInformation ::= SEQUENCE {
    policyIdentifier   CertPolicyId,
    policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    PolicyQualifierInfo OPTIONAL }

    CertPolicyId ::= OBJECT IDENTIFIER

    PolicyQualifierInfo ::= SEQUENCE {
    policyQualifierId  PolicyQualifierId,
    qualifier          ANY DEFINED BY policyQualifierId }

    -- policyQualifierIds for Internet policy qualifiers

    id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
    id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
    id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }

*/
class CertificatePolicies final : public ExtensionBase
{
public:
    CertificatePolicies() : ExtensionBase(id_ce_certificatePolicies) {}

    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSet, certificatePolicies, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        size_t cbSize = 0;
        size_t cbPrefix = 0;
        DerDecode decoder{in, cbData};
        bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, certificatePolicies);

        if (ret)
        {
            cbData = cbSize;
            //cbUsed = cbSize + cbPrefix;
        }

        return ret;
    }

    const std::vector<PolicyInformation> &GetPolicyInformationVector() const { return certificatePolicies; }

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = GetEncodedSize(certificatePolicies));
    }

    std::vector<PolicyInformation> certificatePolicies;
};

class ESSCertID final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = certHash.EncodedSize() + issuerSerial.EncodedSize());
    }

    Hash certHash;             // must be sha1
    IssuerSerial issuerSerial; // Optional
};

class SigningCertificate final : public DerBase
{
    /*
	id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
	member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
	smime(16) id-aa(2) 12 }
	*/
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = GetEncodedSize(certs) + GetEncodedSize(policies));
    }

    std::vector<ESSCertID> certs;
    std::vector<PolicyInformation> policies;
};

class ESSCertIDv2 final : public DerBase
{
public:
    ESSCertIDv2(HashAlgorithm alg = HashAlgorithm::SHA256) : hashAlgorithm(alg) {}

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = hashAlgorithm.EncodedSize() + certHash.EncodedSize() + issuerSerial.EncodedSize());
    }

    AlgorithmIdentifier hashAlgorithm; // Default sha256
    Hash certHash;
    IssuerSerial issuerSerial; // Optional
};

class SigningCertificateV2 final : public DerBase
{
    /*
	id-aa-signingCertificateV2 OBJECT IDENTIFIER ::= { iso(1)
	member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
	smime(16) id-aa(2) 47 }
	*/
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    void AddSigningCert(const ESSCertIDv2 &certID)
    {
        certs.push_back(certID);
    }

    void AddPolicyInformation(const PolicyInformation &policy)
    {
        policies.push_back(policy);
    }

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(certs) + GetEncodedSize(policies);
        return cbData;
    }

    std::vector<ESSCertIDv2> certs;
    std::vector<PolicyInformation> policies;
};

typedef OctetString OtherHashValue;

class OtherHashAlgAndValue final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = hashAlgorithm.EncodedSize() + hashValue.EncodedSize();
        return cbData;
    }

    AlgorithmIdentifier hashAlgorithm;
    OtherHashValue hashValue;
};

typedef ObjectIdentifier SigPolicyQualifierId;

class SigPolicyQualifierInfo final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = sigPolicyQualifierId.EncodedSize() + sigQualifier.EncodedSize());
    }

    SigPolicyQualifierId sigPolicyQualifierId;
    AnyType sigQualifier;
};

typedef ObjectIdentifier SigPolicyId;
typedef OtherHashAlgAndValue SigPolicyHash;

class SignaturePolicyId final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = sigPolicyId.EncodedSize() + sigPolicyHash.EncodedSize() + GetEncodedSize(sigPolicyQualifiers));
    }

    SigPolicyId sigPolicyId;
    SigPolicyHash sigPolicyHash;
    std::vector<SigPolicyQualifierInfo> sigPolicyQualifiers;
};

typedef Null SignaturePolicyImplied;

/*
id-aa-ets-sigPolicyId OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
smime(16) id-aa(2) 15 }
*/

/*SignaturePolicy is a union, but SignaturePolicyImplied signaturePolicyImplied must not be used*/
typedef SignaturePolicyId SignaturePolicy;

/*
id-spq-ets-uri OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
smime(16) id-spq(5) 1 }
*/

/*
id-spq-ets-unotice OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
smime(16) id-spq(5) 2 }
*/

class SPUserNotice final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = noticeRef.EncodedSize() + explicitText.EncodedSize());
    }

    NoticeReference noticeRef;
    DisplayText explicitText;
};

typedef ObjectIdentifier CommitmentTypeIdentifier;

/* Defined CommitmentTypeIdentifiers 
id-cti-ets-proofOfOrigin OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 1}

id-cti-ets-proofOfReceipt OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 2}

id-cti-ets-proofOfDelivery OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 3}

id-cti-ets-proofOfSender OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6) 4}

id-cti-ets-proofOfApproval OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 5}

id-cti-ets-proofOfCreation OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) cti(6) 6}
*/

class CommitmentTypeQualifier final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = commitmentTypeIdentifier.EncodedSize() + qualifier.EncodedSize());
    }

    CommitmentTypeIdentifier commitmentTypeIdentifier;
    AnyType qualifier; // At the moment, none of these are defined, so must be Null
};

/*
id-aa-ets-commitmentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 16}
*/

class CommitmentTypeIndication final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = commitmentTypeId.EncodedSize() + GetEncodedSize(commitmentTypeQualifier));
    }

    CommitmentTypeIdentifier commitmentTypeId;
    std::vector<CommitmentTypeQualifier> commitmentTypeQualifier;
};

/*
id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 17}
*/

typedef std::vector<DirectoryString> PostalAddress; // 1-6 items

class SignerLocation final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

protected:
    virtual size_t SetDataSize() override
    {
        return (cbData = countryName.EncodedSize() + localityName.EncodedSize() + GetEncodedSize(postalAdddress));
    }

    DirectoryString countryName;
    DirectoryString localityName;
    PostalAddress postalAdddress;
};

/*
id-aa-ets-signerAttr OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 18}
*/
typedef std::vector<Attribute> ClaimedAttributes;
typedef AttributeCertificate CertifiedAttributes;

class SignerAttribute final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(claimedAttributes) + certifiedAttributes.EncodedSize();
        return cbData;
    }

    ClaimedAttributes claimedAttributes;
    CertifiedAttributes certifiedAttributes;
};

/* From RFC 3161 - https://www.rfc-editor.org/rfc/rfc3161.txt */
class MessageImprint final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = hashAlgorithm.EncodedSize() + hashedMessage.EncodedSize();
        return cbData;
    }

    AlgorithmIdentifier hashAlgorithm;
    OctetString hashedMessage;
};

typedef ObjectIdentifier TSAPolicyId;

class TimeStampReq final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (
            cbData =
                version.EncodedSize() +
                messageImprint.EncodedSize() +
                reqPolicy.EncodedSize() +
                nonce.EncodedSize() +
                certReq.EncodedSize() +
                extensions.EncodedSize());
    }

    Integer version; // set to 1
    MessageImprint messageImprint;
    TSAPolicyId reqPolicy;
    Integer nonce;
    Boolean certReq;
    Extensions extensions;
};

typedef Integer PKIStatus;
/*
granted                (0),
-- when the PKIStatus contains the value zero a TimeStampToken, as
requested, is present.
grantedWithMods        (1),
-- when the PKIStatus contains the value one a TimeStampToken,
with modifications, is present.
rejection              (2),
waiting                (3),
revocationWarning      (4),
-- this message contains a warning that a revocation is
-- imminent
revocationNotification (5)
-- notification that a revocation has occurred   
*/

typedef BitString PKIFailureInfo;
/*
badAlg               (0),
-- unrecognized or unsupported Algorithm Identifier
badRequest           (2),
-- transaction not permitted or supported
badDataFormat        (5),
-- the data submitted has the wrong format
timeNotAvailable    (14),
-- the TSA's time source is not available
unacceptedPolicy    (15),
-- the requested TSA policy is not supported by the TSA.
unacceptedExtension (16),
-- the requested extension is not supported by the TSA.
addInfoNotAvailable (17)
-- the additional information requested could not be understood
-- or is not available
systemFailure       (25)
-- the request cannot be handled due to system failure  
*/

class PKIFreeText final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override
    {
        EncodeSetOrSequenceOf(DerType::ConstructedSet, values, out);
    }

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};
        return decoder.DecodeSet(values);
    }

protected:
    virtual size_t SetDataSize() override
    {
        cbData = 0;
        for (uint32_t i = 0; i < values.size(); ++i)
        {
            cbData += values[i].EncodedSize();
        }
        return cbData;
    }

    std::vector<UTF8String> values;
};

typedef ContentInfo TimeStampToken; // id-signedData

class PKIStatusInfo final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = status.EncodedSize() + statusString.EncodedSize() + failInfo.EncodedSize();
        return cbData;
    }

    PKIStatus status;
    PKIFreeText statusString;
    PKIFailureInfo failInfo;
};

class TimeStampResp final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = status.EncodedSize() + timeStampToken.EncodedSize();
        return cbData;
    }

    PKIStatusInfo status;
    TimeStampToken timeStampToken;
};

class Accuracy final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = seconds.EncodedSize() + millis.EncodedSize() + micros.EncodedSize();
        return cbData;
    }

    Integer seconds;
    Integer millis;
    Integer micros;
};

class TSTInfo final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (
            cbData = version.EncodedSize() +
                     policy.EncodedSize() +
                     messageImprint.EncodedSize() +
                     serialNumber.EncodedSize() +
                     genTime.EncodedSize() +
                     accuracy.EncodedSize() +
                     ordering.EncodedSize() +
                     nonce.EncodedSize() +
                     tsa.EncodedSize() +
                     extensions.EncodedSize());
    }

    Integer version; // set to 1
    TSAPolicyId policy;
    MessageImprint messageImprint;
    Integer serialNumber;
    GeneralizedTime genTime;
    Accuracy accuracy;
    Boolean ordering;
    Integer nonce;
    GeneralName tsa;
    Extensions extensions;
};

/*
id-aa-ets-contentTimestamp OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 20}
*/

typedef TimeStampToken ContentTimestamp;

/*
id-aa-signatureTimeStampToken OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 14}
*/

typedef TimeStampToken SignatureTimeStampToken;

/*
id-aa-ets-certificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 21}
*/

/* OtherHash is a union, but OtherHashValue sha1Hash Should not be used, so typedef */
// TBD - might need to restore it if there's a back compat need
typedef OtherHashAlgAndValue OtherHash;

class OtherCertId final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = otherCertHash.EncodedSize() + issuerSerial.EncodedSize());
    }

    OtherHash otherCertHash;
    IssuerSerial issuerSerial;
};

typedef std::vector<OtherCertId> CompleteCertificateRefs;

/*
id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}
*/

class CrlIdentifier final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = crlissuer.EncodedSize() + crlIssuedTime.EncodedSize() + crlNumber.EncodedSize();
        return cbData;
    }

    Name crlissuer;
    UTCTime crlIssuedTime;
    Integer crlNumber;
};

class CrlValidatedID final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = crlHash.EncodedSize() + crlIdentifier.EncodedSize());
    }

    OtherHash crlHash;
    CrlIdentifier crlIdentifier;
};

typedef std::vector<CrlValidatedID> CRLListID;

// SHA-1 hash of responder's public key
// (excluding the tag and length fields)
typedef OctetString KeyHash;

enum class ResponderIDType
{
    NotSet,
    Name,
    KeyHash
};

class ResponderID final : public DerBase
{
public:
    ResponderID(ResponderIDType t = ResponderIDType::NotSet) : type(t) {}

    virtual void Encode(std::span<std::byte> out)
    {
        value.Encode(out);
    }

    bool Decode(std::span<const std::byte> in)
    {
        // TODO - assign type value once we can determine what this is
        return value.Decode(in);
    }

    void SetValue(Name &byName) { SetValue(ResponderIDType::Name, byName); }
    void SetValue(KeyHash &byKey) { SetValue(ResponderIDType::KeyHash, byKey); }

private:
    virtual size_t SetDataSize() override
    {
        cbData = value.EncodedSize();
        return cbData;
    }

    template <typename T>
    void SetValue(ResponderIDType t, T &in)
    {
        type = t;
        value.SetValue(in);
    }

    ResponderIDType type;
    AnyType value;
};

class OcspIdentifier final : public DerBase
{
public:
    virtual size_t SetDataSize() override
    {
        cbData = ocspResponderID.EncodedSize() + producedAt.EncodedSize();
        return cbData;
    }

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    ResponderID ocspResponderID; //As in OCSP response data
    GeneralizedTime producedAt;
};

class OcspResponsesID final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = ocspIdentifier.EncodedSize() + ocspRepHash.EncodedSize();
        return cbData;
    }

    OcspIdentifier ocspIdentifier;
    OtherHash ocspRepHash;
};

class OcspListID final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;

    virtual bool Decode(std::span<const std::byte> in) override
    {
        DerDecode decoder{in, cbData};
        return decoder.DecodeSet(ocspResponses);
    }

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(ocspResponses);
        return cbData;
    }

    std::vector<OcspResponsesID> ocspResponses;
};

typedef ObjectIdentifier OtherRevRefType;

class OtherRevRefs final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = otherRevRefType.EncodedSize() + otherRevRefs.EncodedSize();
        return cbData;
    }

    OtherRevRefType otherRevRefType;
    AnyType otherRevRefs;
};

class CrlOcspRef final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(crlids) + ocspids.EncodedSize() + otherRev.EncodedSize();
        return cbData;
    }

    CRLListID crlids;
    OcspListID ocspids;
    OtherRevRefs otherRev;
};

typedef std::vector<CrlOcspRef> CompleteRevocationRefs;

/*
id-aa-ets-certValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 23}
*/

typedef std::vector<Certificate> CertificateValues;

/*
id-aa-ets-revocationValues OBJECT IDENTIFIER ::= { iso(1)
member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 24}
*/

typedef ObjectIdentifier OtherRevValType;

class OtherRevVals final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = otherRevValType.EncodedSize() + otherRevVals.EncodedSize();
        return cbData;
    }

    OtherRevValType otherRevValType;
    AnyType otherRevVals;
};

typedef Null UnknownInfo;

enum class CRLReasonValue
{
    unspecified = (0),
    keyCompromise = (1),
    cACompromise = (2),
    affiliationChanged = (3),
    superseded = (4),
    cessationOfOperation = (5),
    certificateHold = (6),
    removeFromCRL = (8),
    privilegeWithdrawn = (9),
    aACompromise = (10)
};

class CRLReason : public Enumerated
{
public:
    CRLReason(CRLReasonValue v = CRLReasonValue::unspecified) : Enumerated(static_cast<std::byte>(v)) {}

    void ToString(std::string &str)
    {
        switch (static_cast<CRLReasonValue>(this->GetValue()))
        {
        case CRLReasonValue::unspecified:
            str = "unspecified";
            break;

        case CRLReasonValue::keyCompromise:
            str = "keyCompromise";
            break;

        case CRLReasonValue::cACompromise:
            str = "cACompromise";
            break;

        case CRLReasonValue::affiliationChanged:
            str = "affiliationChanged";
            break;

        case CRLReasonValue::superseded:
            str = "superseded";
            break;
        case CRLReasonValue::cessationOfOperation:
            str = "cessationOfOperation";
            break;

        case CRLReasonValue::certificateHold:
            str = "certificateHold";
            break;

        case CRLReasonValue::removeFromCRL:
            str = "removeFromCRL";
            break;

        case CRLReasonValue::privilegeWithdrawn:
            str = "privilegeWithdrawn";
            break;

        case CRLReasonValue::aACompromise:
            str = "aACompromise";
            break;

        default:
            str = "unknown revocation reason";
            break;
        }
    }
};

class RevokedInfo final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData = revocationTime.EncodedSize() + revocationReason.EncodedSize());
    }

    GeneralizedTime revocationTime;
    CRLReason revocationReason;
};

enum class CertStatusType
{
    Good,
    Revoked,
    Unknown
};

// Go ahead and make the CertStatus a class
// It is actually a CHOICE in the ASN.1, but good and unknown are both
// mapped to the NULL type
class CertStatus final : public DerBase
{
public:
    CertStatus() : type(CertStatusType::Unknown) {}

    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

    size_t EncodedSize() const override
    {
        if (type != CertStatusType::Revoked)
            return 2; // Null::EncodedSize()

        return DerBase::EncodedSize();
    }

private:
    virtual size_t SetDataSize() override
    {
        if (type != CertStatusType::Revoked)
            return 0; // No data for Null

        cbData = revoked.EncodedSize();
        return cbData;
    }

    CertStatusType type;
    RevokedInfo revoked;
};

class CertID final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData =
            hashAlgorithm.EncodedSize() +
            issuerNameHash.EncodedSize() +
            issuerKeyHash.EncodedSize() +
            serialNumber.EncodedSize();
        return cbData;
    }

    AlgorithmIdentifier hashAlgorithm;
    OctetString issuerNameHash;
    OctetString issuerKeyHash;
    CertificateSerialNumber serialNumber;
};

class SingleResponse final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        return (cbData =
                    certID.EncodedSize() +
                    certStatus.EncodedSize() +
                    thisUpdate.EncodedSize() +
                    nextUpdate.EncodedSize() +
                    singleExtensions.EncodedSize());
    }

    CertID certID;
    CertStatus certStatus;
    GeneralizedTime thisUpdate;
    GeneralizedTime nextUpdate;
    Extensions singleExtensions;
};

class ResponseData final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData =
            version.EncodedSize() +
            responderID.EncodedSize() +
            producedAt.EncodedSize() +
            GetEncodedSize(responses) +
            extensions.EncodedSize();

        return cbData;
    }

    Integer version; // default v1
    ResponderID responderID;
    GeneralizedTime producedAt;
    std::vector<SingleResponse> responses;
    Extensions extensions;
};

class BasicOCSPResponse final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData =
            tbsResponseData.EncodedSize() +
            signatureAlgorithm.EncodedSize() +
            signature.EncodedSize() +
            GetEncodedSize(certs);

        return cbData;
    }

    ResponseData tbsResponseData;
    AlgorithmIdentifier signatureAlgorithm;
    BitString signature;
    std::vector<Certificate> certs;
};

class RevocationValues final : public DerBase
{
public:
    virtual void Encode(std::span<std::byte> out) override;
    virtual bool Decode(std::span<const std::byte> in) override;

private:
    virtual size_t SetDataSize() override
    {
        cbData = GetEncodedSize(crlVals) + GetEncodedSize(ocspVals) + otherRevVals.EncodedSize();
        return cbData;
    }

    std::vector<CertificateList> crlVals;
    std::vector<BasicOCSPResponse> ocspVals;
    OtherRevVals otherRevVals;
};

/*
id-aa-ets-escTimeStamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 25}
*/
typedef TimeStampToken ESCTimeStampToken;

/*
id-aa-ets-certCRLTimestamp OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 26}
*/
typedef TimeStampToken TimestampedCertsCRLs;

/*
id-aa-ets-archiveTimestampV2  OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 48}
*/

typedef TimeStampToken ArchiveTimeStampToken;

/*
id-aa-ets-attrCertificateRefs OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 44}
*/

typedef std::vector<OtherCertId> AttributeCertificateRefs;

/*
id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
smime(16) id-aa(2) 45}
*/

typedef std::vector<CrlOcspRef> AttributeRevocationRefs;
