#pragma once

/*
    Use this to extract a Certificate to a structure suitable for
    serializing to XML. Use only standard library types here.
*/

namespace ctx
{
    template <typename T>
    void ToString(const T& t, std::string& out)
    {
        std::stringstream strstm;
        strstm << t;
        out = strstm.str();
    }

    class xAnyType
    {
    public:
        void Convert(const AnyType& a)
        {
            ToString(a, hexValue);
        }

        std::string hexValue;
    };

    class xOctetString
    {
    public:

        void Convert(const OctetString& o)
        {
            ToString(o, str);
        }

        std::string str;
    };

    class xCertificateSerialNumber
    {
    public:

        void Convert(const CertificateSerialNumber& csn)
        {
            ToString(csn, str);
        }

        std::string str;
    };

    class xObjectIdentifier
    {
    public:

        void Convert(const ObjectIdentifier& oi)
        {
            // We could have an unknown OID, won't have a label for it
            const char* oidLabel = oi.GetOidLabel();

            ctx::ToString(oi, oid);
            tag = oidLabel == nullptr ? "unknown" : oidLabel;
        }

        std::string oid;
        std::string tag;
    };

    class xAlgorithmIdentifier
    {
    public:
        void Convert(const AlgorithmIdentifier& ai)
        {
            oid.Convert(ai.GetAlgorithm());
            params.Convert(ai.GetParameters());
        }

        xObjectIdentifier oid;
        xAnyType params;
    };

    class xAttributeTypeAndValue
    {
    public:
        void Convert(const AttributeTypeAndValue& atv)
        {
            oid.Convert(atv.GetOid());
            value.Convert(atv.GetValue());
        }

        xObjectIdentifier oid;
        xAnyType value;
    };

    /*
        RelativeDistinguishedName - contains a sequence (usually 1) of AttributeTypeAndValue elements
        Name - contains a sequence of RelativeDistinguishedName
    */

    class xValidity
    {
    public:
        void Convert(const Validity& v)
        {
            ConvertTime(v.GetNotBefore(), notBefore);
            ConvertTime(v.GetNotAfter(), notAfter);
        }

        std::string notBefore;
        std::string notAfter;

    private:
        void ConvertTime(const Time& t, std::string& out);
    };

    class xSubjectPublicKeyInfo
    {
    public:
        void Convert(const SubjectPublicKeyInfo& spi)
        {
            algId.Convert(spi.GetAlgorithm());
            ToString(spi.GetSubjectPublicKey(), subjectPublicKey);
        }

        xAlgorithmIdentifier algId;
        std::string subjectPublicKey;
    };

    class xKeyUsage
    {
    public:
        void Convert(const KeyUsage& ku)
        {
            KeyUsageValue usageValue = ku.GetKeyUsage();
            usage = *reinterpret_cast<std::uint32_t*>(&usageValue);
        }

        std::uint32_t usage;
    };

    /*
    ExtendedKeyUsage is a sequence of ObjectIdentifier

    */

    class xSubjectKeyIdentifier
    {
    public:
        void Convert(const SubjectKeyIdentifier& ski)
        {
            ToString(ski.GetKeyIdentifer(), subjectKeyIdentifier);
        }

        std::string subjectKeyIdentifier;
    };

    class xDirectoryString
    {
    public:
        void Convert(const DirectoryString& ds);

        std::string directoryString;
    };

    class xEDIPartyName
    {
        void Convert(const EDIPartyName& epn)
        {
            nameAssigner.Convert(epn.GetNameAssigner());
            partyName.Convert(epn.GetPartyName());
        }

        xDirectoryString nameAssigner;
        xDirectoryString partyName;
    };

    /* 
        GeneralName TODO 
        GeneralNames is just a sequence of GeneralName
    */

    /* TODO AuthorityKeyIdentifier */



} // namespace ctx

bool CertificateToXml(const Certificate& cert, const char* szXmlFile);
