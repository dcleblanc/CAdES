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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	Attribute(const char* oid) : attrType(oid)
	{

	}

	Attribute() {};
	Attribute(const Attribute& rhs) : attrType(rhs.attrType)
	{
		attrValues.insert(attrValues.begin(), rhs.attrValues.begin(), rhs.attrValues.end());
	}

	virtual void Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	void AddAttributeValue(const AttributeValue& value)
	{
		attrValues.push_back(value);
	}

private:
	virtual size_t SetDataSize() override
	{
		size_t cbNeeded = 0; // For the set byte

							 // First, calculate how much is needed for the set of attrValues
		for (size_t i = 0; i < attrValues.size(); ++i)
		{
			cbNeeded += attrValues[i].EncodedSize();
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
        EncodeSetOrSequenceOf(DerType::ConstructedSet, attrs, pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		return DecodeSet(pIn, cbIn, cbUsed, attrs);
	}

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
        EncodeHelper eh(cbUsed);

        eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

        // This is a sequence of sets of AttributeTypeAndValue
        for (size_t item = 0; item < name.size(); ++item)
        {
            name[item].Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
            eh.Update();
        }
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
        SequenceHelper sh(cbUsed);

        switch (sh.Init(pIn, cbIn))
        {
        case DecodeResult::Failed:
            return false;
        case DecodeResult::Null:
            return true;
        case DecodeResult::Success:
            break;
        }

        // This is a sequence of sets of AttributeTypeAndValue
        for (size_t item = 0; sh.DataSize() > 0; ++item)
        {
            RelativeDistinguishedName rdn;
            if (!rdn.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
                return false;

            name.push_back(rdn);
            sh.Update();
        }

        return true;
	}

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		rdnSequence.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
        // A Name is a CHOICE, but there's only one possible type, which is an rdnSequence
        return rdnSequence.Decode(pIn, cbIn, cbUsed);
	}

    virtual size_t EncodedSize() override
    {
        return rdnSequence.EncodedSize();
    }

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		cbData = issuer.EncodedSize() + serialNumber.EncodedSize();
		return cbData;
	}

	Name issuer;
	CertificateSerialNumber serialNumber;
};

typedef OctetString SubjectKeyIdentifier;

enum class SignerIdentifierType
{
	NotSet,
	Issuer,
	SubjectKey
};

class SignerIdentifier final : public DerBase
{
public:
	SignerIdentifier(SignerIdentifierType t = SignerIdentifierType::NotSet) : type(t) {}

	void SetValue(IssuerAndSerialNumber& issuerAndSerialNumber) { SetValue(SignerIdentifierType::Issuer, issuerAndSerialNumber); }
	void SetValue(SubjectKeyIdentifier& subjectKeyIdentifier) { SetValue(SignerIdentifierType::SubjectKey, subjectKeyIdentifier); }

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		return value.Decode(pIn, cbIn, cbUsed);
	}

	AnyType value;

private:
	virtual size_t SetDataSize() override
	{
		cbData = value.EncodedSize();
		return cbData;
	}

	template <typename T>
	void SetValue(SignerIdentifierType t, T& in)
	{
		type = t;
		value.SetValue(in);
	}

	SignerIdentifierType type;
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	ObjectIdentifier extnID;
	Boolean critical;
	OctetString extnValue;
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

	AlgorithmIdentifier(const char* oid) : algorithm(oid)
	{
		parameters.SetNull();
	}

	AlgorithmIdentifier() = default;

	virtual size_t SetDataSize() override
	{
		cbData = algorithm.EncodedSize() + parameters.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

protected:
	virtual size_t SetDataSize() override
	{
		return	(
				cbData =
				version.EncodedSize() +
				sid.EncodedSize() +
				digestAlgorithm.EncodedSize() +
				GetEncodedSize(signedAttrs) +
				signatureAlgorithm.EncodedSize() +
				signature.EncodedSize() +
				GetEncodedSize(unsignedAttrs)
				);
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

protected:
	virtual size_t SetDataSize() override
	{
		return (cbData = otherCertFormat.EncodedSize() + otherCert.EncodedSize());
	}

	ObjectIdentifier otherCertFormat;
	AnyType otherCert; // DEFINED BY otherCertFormat 
};

typedef BitString UniqueIdentifier;

class SubjectPublicKeyInfo final : public DerBase
{
public:
	virtual size_t SetDataSize() override
	{
		cbData = algorithm.EncodedSize() + subjectPublicKey.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
        EncodeSetOrSequenceOf(DerType::ConstructedSequence, values, pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		// This is actually a SEQUENCE, oddly, seems it should be a set
		// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

		return DecodeSequenceOf(pIn, cbIn, cbUsed, values);
	}

	std::vector<Extension> values;
};

class Validity final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	TBSCertificate() : version(0), issuerUniqueID(1), subjectUniqueID(2), extensions(3){}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	ContextSpecificHolder<Integer> version;
	CertificateSerialNumber serialNumber;
	AlgorithmIdentifier signature;
	Name issuer;
	Validity validity;
	Name subject;
	SubjectPublicKeyInfo subjectPublicKeyInfo;
	// Note - optional fields may be missing, not have null placeholders
	ContextSpecificHolder<UniqueIdentifier> issuerUniqueID;  // optional, will have value 0xA1
	ContextSpecificHolder<UniqueIdentifier> subjectUniqueID; // optional, will have value 0xA2
	ContextSpecificHolder<Extensions> extensions;            // optional, will have value 0xA3
};

class Certificate final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		cbData = tbsCertificate.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize();
		return cbData;
	}

	TBSCertificate tbsCertificate;
	AlgorithmIdentifier signatureAlgorithm;
	BitString signatureValue;
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
	DigestedObjectType(DigestedObjectTypeValue v = DigestedObjectTypeValue::publicKey) : Enumerated(static_cast<unsigned char>(v)) {}
};

enum class DirectoryStringType
{
	NotSet,
	Printable, // This, or a UTF8 string, is what should be used currently
	Universal,
	BMP
};

// Ignore next as likely obsolete, implement if this is incorrect
//	TeletexString teletexString;
/*
	Note - from https://tools.ietf.org/html/rfc5280#section-4.1.2.6

	Section (c)
	TeletexString, BMPString, and UniversalString are included
	for backward compatibility, and SHOULD NOT be used for
	certificates for new subjects.
*/

class DirectoryString final : public DerBase
{
public:
	DirectoryString(DirectoryStringType t = DirectoryStringType::NotSet) : type(t) {}
	void SetValue(PrintableString& printableString) { SetValue(DirectoryStringType::Printable, printableString); }
	void SetValue(UniversalString& universalString) { SetValue(DirectoryStringType::Universal, universalString); }
	void SetValue(BMPString& bmpString) { SetValue(DirectoryStringType::BMP, bmpString); }

	void Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		if (!value.Decode(pIn, cbIn, cbUsed))
			return false;

		switch (static_cast<DerType>(pIn[0]))
		{
		case DerType::PrintableString:
			type = DirectoryStringType::Printable;
			break;

		case DerType::UniversalString:
			type = DirectoryStringType::Universal;
			break;

		case DerType::BMPString:
			type = DirectoryStringType::BMP;
			break;

		default:
			cbUsed = 0;
			return false;
		}

		return true;
	}

	virtual size_t SetDataSize() override
	{
		cbData = value.EncodedSize();
		return cbData;
	}

	AnyType value;
private:
	template <typename T>
	void SetValue(DirectoryStringType t, T& in)
	{
		type = t;
		value.SetValue(in);
	}

	DirectoryStringType type;
};

typedef Attribute OtherName;

class EDIPartyName final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

protected:
	virtual size_t SetDataSize() override
	{
		return (cbData = nameAssigner.EncodedSize() + partyName.EncodedSize());
	}

	DirectoryString nameAssigner;
	DirectoryString partyName;
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
// Note - definition for ORAddress is in RFC 3280, and is complex.
// Hopefully, we won't need it.

*/

enum class GeneralNameType
{
	NotSet,
	Other,  // otherName
	RFC822, // rfc822Name
	DNS,    // dNSName
	Directory, // directoryName
	EDIParty,  // ediPartyName
	URI,       // uniformResourceIdentifier
	IP,
	RegisteredID
};

class GeneralName final : public DerBase
{
public:
	GeneralName(GeneralNameType t = GeneralNameType::NotSet) : type(t) {}
	virtual ~GeneralName() = default;

	virtual size_t SetDataSize() override
	{
		cbData = value.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		return value.Decode(pIn, cbIn, cbUsed);
	}

	void SetValue(OtherName& in) { SetValue(GeneralNameType::Other, in); }
	void SetValue(Name& directoryName) { SetValue(GeneralNameType::Directory, directoryName); }
	void SetValue(EDIPartyName& ediPartyName) { SetValue(GeneralNameType::EDIParty, ediPartyName); }
	void SetValue(OctetString& iPAddress) { SetValue(GeneralNameType::IP, iPAddress); }
	void SetValue(ObjectIdentifier& registeredID) { SetValue(GeneralNameType::RegisteredID, registeredID); }

	// Used for RFC822, DNS, URI
	void SetValue(GeneralNameType t, IA5String in) { SetValue(t, in); }

	AnyType value;

private:
	template <typename T>
	void SetValue(GeneralNameType t, T& in)
	{
		type = t;
		value.SetValue(in);
	}

	GeneralNameType type;

};

class GeneralNames final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		SetDataSize();
        EncodeSetOrSequenceOf(DerType::ConstructedSet, names, pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DecodeSet(pIn, cbIn, cbUsed, names);
	}

protected:

	virtual size_t SetDataSize() override
	{
		cbData = GetDataSize(names);
		return cbData;
	}

	std::vector<GeneralName> names;
};


class IssuerSerial final : public DerBase
{
public:
	virtual size_t SetDataSize() override
	{
		cbData = issuer.EncodedSize() + serial.EncodedSize() + issuerUID.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	DigestedObjectType digestedObjectType;
	ObjectIdentifier otherObjectTypeID;
	AlgorithmIdentifier digestAlgorithm;
	BitString objectDigest;
};

class Holder final : public DerBase
{
public:
	Holder(){}

	virtual size_t SetDataSize() override
	{
		cbData = baseCertificateID.EncodedSize() + entityName.EncodedSize() + objectDigestInfo.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	IssuerSerial baseCertificateID; // optional
	GeneralNames entityName;
	ObjectDigestInfo objectDigestInfo;
};

class AttCertValidityPeriod final : public DerBase
{
public:
	virtual size_t SetDataSize() override { return (cbData = notBeforeTime.EncodedSize() + notAfterTime.EncodedSize()); }
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;


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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	AttCertVersion version; // set this to CertVersionValue::v2
	Holder holder;
	AttCertIssuer issuer;
	AlgorithmIdentifier signature;
	CertificateSerialNumber serialNumber;
	AttCertValidityPeriod attrCertValidityPeriod;
	std::vector<Attribute> attributes;
	UniqueIdentifier issuerUniqueID; // optional
	Extensions extensions; // optional
};

class AttributeCertificate final : public DerBase
{
public:
	virtual size_t SetDataSize() override
	{
		return (cbData = acinfo.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize());
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

class CertificateChoices final : public DerBase
{
public:
	CertificateChoices(CertificateChoicesType t = CertificateChoicesType::NotSet) : type(t) {}

	void SetValue(Certificate& certificate) { SetValue(CertificateChoicesType::Cert, certificate); }
	void SetValue(AttributeCertificateV2& v2AttrCert) { SetValue(CertificateChoicesType::AttributeCert, v2AttrCert); }
	void SetValue(OtherCertificateFormat& other) { SetValue(CertificateChoicesType::OtherCert, other); }

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return value.Decode(pIn, cbIn, cbUsed);
	}

	AnyType value;

protected:
	virtual size_t SetDataSize() override
	{
		return value.SetDataSize();
	}

private:
	template <typename T>
	void SetValue(CertificateChoicesType t, T& in)
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
        EncodeSetOrSequenceOf(DerType::ConstructedSet, entries, pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DecodeSet(pIn, cbIn, cbUsed, entries);
	}

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	Integer version; // optional, must be v2 if present
	AlgorithmIdentifier signature;
	Name issuer;
	Time thisUpdate;
	Time nextUpdate; // optional
	RevokedCertificates revokedCertificates;
	CrlExtensions crlExtensions; // optional
};

class CertificateList final : public DerBase
{
public:
	virtual size_t SetDataSize() override
	{
		cbData = tbsCertList.EncodedSize() + signatureAlgorithm.EncodedSize() + signatureValue.EncodedSize();
		return cbData;
	}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	TBSCertList tbsCertList;
	AlgorithmIdentifier signatureAlgorithm;
	BitString signatureValue;
};

class OtherRevocationInfoFormat final : public DerBase
{
public:
	ObjectIdentifier otherRevInfoFormat;
	AnyType otherRevInfo;

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

protected:
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

	void SetValue(CertificateList& crl) { SetValue(RevocationInfoChoiceType::CRL, crl); }
	void SetValue(OtherRevocationInfoFormat& other) { SetValue(RevocationInfoChoiceType::Other, other); }

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return value.Decode(pIn, cbIn, cbUsed);
	}

	AnyType value;

protected:
	virtual size_t SetDataSize() override
	{
		return cbData = value.SetDataSize();
	}

private:
	template <typename T>
	void SetValue(RevocationInfoChoiceType t, T& in)
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

protected:
	virtual size_t SetDataSize() override
	{
		return (
			cbData = version.EncodedSize() +
			GetEncodedSize(digestAlgorithms) +
			encapContentInfo.EncodedSize() +
			GetEncodedSize(certificates) +
			GetEncodedSize(crls) +
			GetEncodedSize(signerInfos)
			);
	}

	CMSVersion version;
	DigestAlgorithmIdentifiers digestAlgorithms;
	EncapsulatedContentInfo encapContentInfo;
	CertificateSet certificates; //implicit, optional
	RevocationInfoChoices crls; //implicit, optional
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	void SetValue(VisibleString& visibleString) { SetValue(DisplayTextType::Visible, visibleString); }
	void SetValue(BMPString& bmpString) { SetValue(DisplayTextType::BMP, bmpString); }
	void SetValue(UTF8String& utf8String) { SetValue(DisplayTextType::UTF8, utf8String); }

	virtual size_t SetDataSize() override
	{
		cbData = value.EncodedSize();
		return cbData;
	}

	void Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	AnyType value;
private:
	template <typename T>
	void SetValue(DisplayTextType t, T& in)
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	DisplayText organization;
	std::vector<Integer> noticeNumbers;
};

class UserNotice final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		return (cbData = policyIdentifier.EncodedSize() + GetEncodedSize(policyQualifiers));
	}

	CertPolicyId policyIdentifier;
	std::vector<PolicyQualifierInfo> policyQualifiers; // optional
};

class ESSCertID final : public DerBase
{
public:

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		return (cbData = certHash.EncodedSize() + issuerSerial.EncodedSize());
	}

	Hash certHash; // must be sha1
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	ESSCertIDv2(HashAlgorithm alg = HashAlgorithm::SHA256) : hashAlgorithm(alg){}

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	void AddSigningCert(const ESSCertIDv2& certID)
	{
		certs.push_back(certID);
	}

	void AddPolicyInformation(const PolicyInformation& policy)
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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

const char id_cti_ets_proofOfOrigin[]   = "1.2.840.113549.1.9.16.1";
const char id_cti_ets_proofOfReceipt[]  = "1.2.840.113549.1.9.16.2";
const char id_cti_ets_proofOfDelivery[] = "1.2.840.113549.1.9.16.3";
const char id_cti_ets_proofOfSender[]   = "1.2.840.113549.1.9.16.4";
const char id_cti_ets_proofOfApproval[] = "1.2.840.113549.1.9.16.5";
const char id_cti_ets_proofOfCreation[] = "1.2.840.113549.1.9.16.6";

class CommitmentTypeQualifier final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		return  (
				cbData =
				version.EncodedSize() +
				messageImprint.EncodedSize() +
				reqPolicy.EncodedSize() +
				nonce.EncodedSize() +
				certReq.EncodedSize() +
				extensions.EncodedSize()
				);
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override
	{
        EncodeSetOrSequenceOf(DerType::ConstructedSet, values, pOut, cbOut, cbUsed);
	}

	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override
	{
		return DecodeSet(pIn, cbIn, cbUsed, values);
	}

protected:
	virtual size_t SetDataSize() override
	{
		cbData = 0;
		for (unsigned int i = 0; i < values.size(); ++i)
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		return
				(
				cbData = version.EncodedSize() +
				policy.EncodedSize() +
				messageImprint.EncodedSize() +
				serialNumber.EncodedSize() +
				genTime.EncodedSize() +
				accuracy.EncodedSize() +
				ordering.EncodedSize() +
				nonce.EncodedSize() +
				tsa.EncodedSize() +
				extensions.EncodedSize()
				);
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed)
	{
		value.Encode(pOut, cbOut, cbUsed);
	}

	bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
	{
		// TODO - assign type value once we can determine what this is
		return value.Decode(pIn, cbIn, cbUsed);
	}

	void SetValue(Name& byName) { SetValue(ResponderIDType::Name, byName); }
	void SetValue(KeyHash& byKey) { SetValue(ResponderIDType::KeyHash, byKey); }

private:
	virtual size_t SetDataSize() override
	{
		cbData = value.EncodedSize();
		return cbData;
	}

	template <typename T>
	void SetValue(ResponderIDType t, T& in)
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

	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

private:
	ResponderID ocspResponderID; //As in OCSP response data
	GeneralizedTime producedAt;
};

class OcspResponsesID final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;

	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override
	{
		return DecodeSet(pIn, cbIn, cbUsed, ocspResponses);
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	CRLReason(CRLReasonValue v = CRLReasonValue::unspecified) : Enumerated(static_cast<unsigned char>(v)) {}
};

class RevokedInfo final : public DerBase
{
public:
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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

	virtual void Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

	virtual size_t EncodedSize()
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

private:
	virtual size_t SetDataSize() override
	{
		return (cbData =
			certID.EncodedSize() +
			certStatus.EncodedSize() +
			thisUpdate.EncodedSize() +
			nextUpdate.EncodedSize() +
			singleExtensions.EncodedSize()
			);
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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
	virtual void Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed) override;
	virtual bool Decode(const unsigned char* pIn, size_t cbIn, size_t& cbUsed) override;

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
