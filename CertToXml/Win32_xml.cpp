#include "../CAdESLib/Common.h"
#include "CertToXml.h"

#include <Windows.h>
#include <xmllite.h>
#include <shlwapi.h>

#pragma comment(lib, "XmlLite.lib")
#pragma comment(lib, "Shlwapi.lib")

class CoInit
{
public:
    CoInit()
    {
        hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    }

    ~CoInit()
    {
        CoUninitialize();
    }

    HRESULT hr;
};

template<typename T>
class ComPtr
{
public:
    ComPtr() : ptr(nullptr) {}
    ComPtr(T* p) { Assign(p); }

    ~ComPtr()
    {
        ptr->Release();
        ptr = nullptr;
    }

    T* Assign(T* p)
    {
        assert(ptr == nullptr);
        ptr = p;
    }

    T* operator=(T* p) { return Assign(p); }
    void** PtrAddr() { return reinterpret_cast<void**>(&ptr); }
    operator IUnknown*() { return static_cast<IUnknown*>(ptr); }
    operator T*() { return ptr; }
    T* operator->() { return ptr; }

    T * ptr;
};

class CertXmlWriter
{
public:
    CertXmlWriter(IXmlWriter * p, const Certificate& _cert) : pWriter(p), cert(_cert) {}

    void WriteStartDocument()
    {
        CheckSuccess(pWriter->WriteStartDocument(XmlStandalone_Omit));
    }

    void WriteMetadata()
    {
        WriteStartElement(L"Metadata");
        {
            std::wstring thumbprint;
            std::wstring thumbprint256;

            ctx::ToString(cert.GetThumbprint(), thumbprint);
            ctx::ToString(cert.GetThumbprint256(), thumbprint256);

            WriteSimpleElement(L"FileName", utf8ToUtf16(cert.GetFileName()));
            WriteSimpleElement(L"Thumbprint", thumbprint);
            WriteSimpleElement(L"Thumbprint256", thumbprint256);
        }
        WriteEndElement();
    }

    void WriteCertificate()
    {
        WriteStartElement(L"Certificate");
        WriteMetadata();
        WriteTbsCertificate();
        WriteSignatureAlgorithm();
        WriteSignatureValue();
        WriteEndElement();
    }

    void WriteVersion()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const Integer& version = tbsCert.GetVersionAsInteger();
        std::wstring wzVersion;

        ctx::ToString(version, wzVersion);

        // This will happen if the version is missing, which indicates a v1 cert
        if (wzVersion.size() == 0)
			wzVersion = L"0";

        WriteSimpleElement(L"Version", wzVersion);
    }

    void WriteSerialNumber()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const Integer& serial = tbsCert.GetSerialNumber();
        std::wstring hexSerial;

        ctx::ToString(serial, hexSerial);
        WriteSimpleElement(L"SerialNumber", hexSerial);
    }

    void WriteSignature()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const AlgorithmIdentifier& algId = tbsCert.GetSignature();

        WriteStartElement(L"Signature");
        WriteAlgorithmIdentifier(algId);
        WriteEndElement();
    }

    void WriteIssuer()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const Name& name = tbsCert.GetIssuer();
        WriteNameElement(L"Issuer", name);
    }

    void WriteSubject()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const Name& name = tbsCert.GetSubject();
        WriteNameElement(L"Subject", name);
    }

    void WriteValidity()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const Validity& validity = tbsCert.GetValidity();
        ctx::xValidity xmlValidity;

        xmlValidity.Convert(validity);

        WriteStartElement(L"Validity");
        WriteSimpleElement(L"NotBefore", xmlValidity.notBefore);
        WriteSimpleElement(L"NotAfter", xmlValidity.notAfter);
        WriteEndElement();
    }

    void WriteSubjectPublicKeyInfo()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        const BitString& publicKey = tbsCert.GetSubjectPublicKeyInfo().GetSubjectPublicKey();
        std::wstring hexKey;

        ctx::ToString(publicKey, hexKey);

        WriteStartElement(L"SubjectPublicKeyInfo");
        {
            WriteStartElement(L"Algorithm");
            WriteAlgorithmIdentifier(tbsCert.GetSubjectPublicKeyInfo().GetAlgorithm());
            WriteEndElement();
            WriteStartElement(L"SubjectPublicKey");
            WriteRawElementString(hexKey);
            WriteEndElement();
        }
        WriteEndElement();
    }

    void WriteIssuerUniqueId()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();

        if (tbsCert.HasIssuerId())
        {
            const UniqueIdentifier& innerUID = tbsCert.GetIssuerId(); // This is just a BitString

            if (innerUID.ValueSize() == 0)
                return;

            std::wstring uid;
            ctx::ToString(innerUID, uid);

            WriteSimpleElement(L"IssuerUniqueID", uid);

        }
    }

    void WriteSubjectUniqueId()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();

        if (tbsCert.HasSubjectId())
        {
            const UniqueIdentifier& innerUID = tbsCert.GetSubjectId(); // This is just a BitString

            if (innerUID.ValueSize() == 0)
                return;

            std::wstring uid;
            ctx::ToString(innerUID, uid);

            WriteSimpleElement(L"SubjectUniqueID", uid);
        }

    }

    template <typename T>
    void DecodeExtension(T& t, const std::vector<std::byte>& extensionBytes)
    {
        size_t cbExtension = extensionBytes.size();
        size_t cbUsed = 0;

        if (cbExtension > 0 && t.Decode(&extensionBytes[0], cbExtension, cbUsed) && cbUsed == cbExtension)
            return;

        throw std::exception("Malformed extension");
    }

    void WriteKeyUsage(const std::vector<std::byte>& extensionBytes)
    {
        KeyUsage ku;
        DecodeExtension(ku, extensionBytes);
        const BitString& bits = ku.GetBitString();
        std::wstring str;

        ctx::ToString(bits, str);

        WriteSimpleElement(L"KeyUsage", str);
    }

    void WriteObjectIdentifier(const wchar_t* wzElementName, const ObjectIdentifier& oid)
    {
        ctx::xObjectIdentifier xOid;
        xOid.Convert(oid);

        WriteStartElement(wzElementName);
        WriteSimpleElement(L"Oid", xOid.oid);
        WriteSimpleElement(L"Tag", xOid.tag);
        WriteEndElement();
    }

    void WriteExtendedKeyUsage(const std::vector<std::byte>& extensionBytes)
    {
        ExtendedKeyUsage eku;
        DecodeExtension(eku, extensionBytes);

        const std::vector<ObjectIdentifier>& oids = eku.GetEkus();

        WriteStartElement(L"ExtendedKeyUsage");
        {
            for (const ObjectIdentifier& oid : oids)
            {
                WriteObjectIdentifier(L"ObjectIdentifier", oid);
            }
        }
        WriteEndElement();
    }

    void WriteSubjectKeyIdentifier(const std::vector<std::byte>& extensionBytes)
    {
        SubjectKeyIdentifier keyId;
        DecodeExtension(keyId, extensionBytes);
        std::wstring hexKeyId;

        ctx::ToString(keyId.GetKeyIdentifer(), hexKeyId);
        WriteSimpleElement(L"SubjectKeyIdentifier", hexKeyId);
    }

    void WriteAttribute(const Attribute& attr)
    {
        const ObjectIdentifier& oid = attr.GetAttrType();
        WriteObjectIdentifier(L"Type", oid);

        // Now have an array of AnyType
        const std::vector<AttributeValue>& attrValues = attr.GetAttrValues();
        for (const AttributeValue& value : attrValues)
        {
            // Don't know what these will be, so just convert to hex
            // See how often we encounter them, develop better parsers if these are common
            std::wstring data;
            value.ToString(data);
            WriteSimpleElement(L"AttributeValue", data);
        }
    }

    void WriteGeneralName(const GeneralName& name)
    {
        WriteStartElement(L"GeneralName");
        {
            GeneralNameType type = name.GetType();

            if (type == GeneralNameType::OtherName)
            {
                OtherName otherName;

                name.GetOtherName(otherName);
                WriteStartElement(L"OtherName");
                WriteAttribute(otherName);
                WriteEndElement();
            }
            else
            if (type == GeneralNameType::rfc822Name)
            {
                IA5String rfc822Name;
                std::wstring str;

                name.GetRFC822Name(rfc822Name);
                ctx::ToString(rfc822Name, str);
                WriteSimpleElement(L"RFC822Name", str);
            }
            else
            if (type == GeneralNameType::dNSName)
            {
                IA5String dnsName;
                std::wstring str;

                name.GetDNSName(dnsName);
                ctx::ToString(dnsName, str);
                WriteSimpleElement(L"DNSName", str);
            }
            else
            if (type == GeneralNameType::x400Address)
            {
                ORAddress oraddr;
                std::wstring str;

                name.GetX400Address(oraddr);
                ctx::ToString(oraddr, str);
                WriteSimpleElement(L"X400Address", str);
            }
            else
            if (type == GeneralNameType::directoryName)
            {
                Name dirName;

                name.GetDirectoryName(dirName);
                WriteNameElement(L"DirectoryName", dirName);
            }
            else
            if (type == GeneralNameType::ediPartyName)
            {
                EDIPartyName partyName;

                name.GetEDIPartyName(partyName);

                WriteStartElement(L"EDIPartyName");
                {
                    const DirectoryString& nameAssigner = partyName.GetNameAssigner();
                    const DirectoryString& partyNameStr = partyName.GetPartyName();
                    std::wstring str;

                    const AnyType& any = nameAssigner.GetValue();
                    ctx::ToString(any, str);

                    WriteSimpleElement(L"NameAssigner", str);
                    str.clear();

                    const AnyType& any2 = partyNameStr.GetValue();
                    ctx::ToString(any2, str);

                    WriteSimpleElement(L"PartyName", str);
                }
                WriteEndElement();
            }
            else
            if (type == GeneralNameType::uniformResourceIdentifier)
            {
                IA5String uri;
                std::wstring str;

                name.GetURI(uri);
                ctx::ToString(uri, str);
                WriteSimpleElement(L"UniformResourceIdentifier", str);
            }
            else
            if (type == GeneralNameType::iPAddress)
            {
                OctetString ipAddr;
                std::wstring str;

                name.GetIpAddress(ipAddr);
                ctx::ToString(ipAddr, str);
                WriteSimpleElement(L"IPAddress", str);
            }
            else
            if (type == GeneralNameType::registeredID)
            {
                ObjectIdentifier oid;

                name.GetRegisteredId(oid);
                WriteObjectIdentifier(L"RegisteredId", oid);
            }
        }

        WriteEndElement();
    }

    void WriteGeneralNames(const GeneralNames& names)
    {
        for (const GeneralName& name : names.GetNames())
        {
            WriteGeneralName(name);
        }
    }
        
    void WriteAuthorityKeyIdentifier(const std::vector<std::byte>& extensionBytes)
    {
        AuthorityKeyIdentifier aki;
        DecodeExtension(aki, extensionBytes);

        // All three of the members in this extension are optional
        WriteStartElement(L"AuthorityKeyIdentifier");
        {
            const OctetString& keyIdentifier = aki.GetKeyIdentifier();
            const GeneralNames& authorityCertIssuer = aki.GetAuthorityCertIssuer();
            const CertificateSerialNumber& certSerialNumber = aki.GetCertificateSerialNumber();

            if (aki.HasKeyIdentifier())
            {
                std::wstring hexValue;
                ctx::ToString(keyIdentifier, hexValue);
                WriteSimpleElement(L"KeyIdentifier", hexValue);
            }

            if (aki.HasAuthorityCertIssuer())
            {
                WriteStartElement(L"AuthorityCertIssuer");
                WriteGeneralNames(authorityCertIssuer);
                WriteEndElement();
            }

            if (aki.HasCertificateSerialNumber())
            {
                std::wstring hexValue;
                ctx::ToString(certSerialNumber, hexValue);
                WriteSimpleElement(L"CertificateSerialNumber", hexValue);
            }
        }
        WriteEndElement();
    }

    void WriteDistributionPoint(const DistributionPoint& point)
    {
        WriteStartElement(L"DistributionPoint");
        {
            if (point.HasDistributionPoint())
            {
                const DistributionPointName& distName = point.GetDistributionPoint();

                if (distName.HasFullName())
                {
                    const GeneralNames& fullName = distName.GetFullName();
                    WriteStartElement(L"FullName");
                    WriteGeneralNames(fullName);
                    WriteEndElement();
                }

                if (distName.HasNameRelativeToCRLIssuer())
                {
                    const RelativeDistinguishedName& rdn = distName.GetNameRelativeToCRLIssuer();
                    WriteStartElement(L"NameRelativeToCRLIssuer");
                    WriteRelativeDistinguishedName(rdn);
                    WriteEndElement();
                }
            }

            if (point.HasReasonFlags())
            {
                const ReasonFlags& flags = point.GetReasonFlags();
                std::wstring str;

                ctx::ToString(flags, str);
                WriteSimpleElement(L"ReasonFlags", str);
            }

            if (point.HasCRLIssuer())
            {
                const GeneralNames& crlIssuer = point.GetCRLIssuer();
                WriteStartElement(L"CRLIssuer");
                WriteGeneralNames(crlIssuer);
                WriteEndElement();
            }
        }
        WriteEndElement();
    }

    void WriteCRLDistributionPoints(const std::vector<std::byte>& extensionBytes)
    {
        CrlDistributionPoints distPoints;
        DecodeExtension(distPoints, extensionBytes);

        const std::vector<DistributionPoint>& distPointVector = distPoints.GetDistributionPoints();

        WriteStartElement(L"CRLDistributionPoints");
        {
            for (const DistributionPoint& point : distPointVector)
            {
                WriteDistributionPoint(point);
            }
        }
        WriteEndElement();
    }

    void WriteAuthorityInfoAccess(const std::vector<std::byte>& extensionBytes)
    {
        AuthorityInfoAccess aia;
        DecodeExtension(aia, extensionBytes);

        const std::vector<AccessDescription>& accessVector = aia.GetAccessDescriptions();

        WriteStartElement(L"AuthorityInfoAccess");
        {
            for (const AccessDescription& accessDesc : accessVector)
            {
                WriteStartElement(L"AccessDescription");
                {
                    const ObjectIdentifier& oid = accessDesc.GetAccessMethod();
                    WriteObjectIdentifier(L"AccessMethod", oid);

                    const GeneralName& name = accessDesc.GetAccessLocation();
                    WriteStartElement(L"AccessLocation");
                    WriteGeneralName(name);
                    WriteEndElement();
                }
                WriteEndElement();
            }
        }
        WriteEndElement();
    }

    void WriteSubjectAltName(const std::vector<std::byte>& extensionBytes)
    {
        SubjectAltName altName;
        DecodeExtension(altName, extensionBytes);

        WriteStartElement(L"SubjectAltName");
        WriteGeneralNames(altName.GetNames());
        WriteEndElement();
    }

    void WriteMicrosoftAppCertPolicies(const std::vector<std::byte>& extensionBytes)
    {
        ApplicationCertPolicies appPolicies;
        DecodeExtension(appPolicies, extensionBytes);

        WriteStartElement(L"ApplicationCertPolicies");
        {
            const std::vector<KeyPurposes>& keyPurposes = appPolicies.GetCertPolicies();

            for (const KeyPurposes& purpose : keyPurposes)
            {
                WriteStartElement(L"KeyPurposes");
                const std::vector<ObjectIdentifier>& oidVector = purpose.GetKeyPurposes();
                // Unsure why these are nested vectors, suspect that this one will only have one element
                for (const ObjectIdentifier& oid : oidVector)
                {
                    WriteObjectIdentifier(L"KeyPurpose", oid);
                }
                WriteEndElement();
            }
        }
        WriteEndElement();
    }

    void WriteCertificatePolicies(const std::vector<std::byte>& extensionBytes)
    {
        CertificatePolicies certPolicies;
        DecodeExtension(certPolicies, extensionBytes);

        const std::vector<PolicyInformation>& policyInfos = certPolicies.GetPolicyInformationVector();

        WriteStartElement(L"CertificatePolicies");
        for (const PolicyInformation& policyInfo : policyInfos)
        {
            const CertPolicyId& certPolicyId = policyInfo.GetPolicyIdentifier();
            const std::vector<PolicyQualifierInfo>& policyQualifiers = policyInfo.GetPolicyQualifiers();

            WriteStartElement(L"PolicyInformation");
            {
                WriteObjectIdentifier(L"CertPolicyId", certPolicyId);

                for (const PolicyQualifierInfo& qualifierInfo : policyQualifiers)
                {
                    const PolicyQualifierId& policyQualifierId = qualifierInfo.GetPolicyQualifierId();
                    const AnyType& qualifier = qualifierInfo.GetQualifier();

                    WriteObjectIdentifier(L"PolicyQualifierId", policyQualifierId);

                    std::wstring str;
                    ctx::ToString(qualifier, str);
                    WriteSimpleElement(L"Qualifier", str);
                }
            }
            WriteEndElement();
        }
        WriteEndElement();
    }

    void WriteCertTemplate(const std::vector<std::byte>& extensionBytes)
    {
        CertTemplate certTemplate;
        DecodeExtension(certTemplate, extensionBytes);

        WriteStartElement(L"CertTemplate");
        {
            std::wstring minor;
            std::wstring major;

            WriteObjectIdentifier(L"ObjectIdentifier", certTemplate.GetObjectIdentifier());

            ctx::ToString(certTemplate.GetMajorVersion(), major);
            ctx::ToString(certTemplate.GetMinorVersion(), minor);
            WriteSimpleElement(L"MajorVersion", major);
            WriteSimpleElement(L"MinorVersion", minor);
        }
        WriteEndElement();
    }

    void WriteRawExtension(const wchar_t* wzName, const AnyType& anyType)
    {
        std::wstring str;
        ctx::ToString(anyType, str);

        WriteStartElement(wzName);
        WriteSimpleElement(L"RawExtensionData", str);
        WriteEndElement();
    }

    void WriteAuthorityKeyIdentifierOld(const std::vector<std::byte>& extensionBytes)
    {
        KeyIdentifierObsolete keyId;
        DecodeExtension(keyId, extensionBytes);
        
        WriteRawExtension(L"AuthorityKeyIdentifierOld", keyId.GetRawExtensionData());
    }

    void WriteBasicConstraints(const std::vector<std::byte>& extensionBytes)
    {
        BasicConstraints basicConstraints;
        DecodeExtension(basicConstraints, extensionBytes);

        WriteStartElement(L"BasicConstraints");
        {
            std::wstring isCa = basicConstraints.GetIsCA() ? L"true" : L"false";
            std::wstring pathLen;

            if (basicConstraints.HasPathLength())
            {
                ctx::ToString(basicConstraints.GetPathLengthConstraint(), pathLen);
            }
            else
            {
                // it isn't present
                /*
                   RFC 5280, 4.2.1.9.  Basic Constraints:

                   A pathLenConstraint of zero indicates that no non-
                   self-issued intermediate CA certificates may follow in a valid
                   certification path.  Where it appears, the pathLenConstraint field
                   MUST be greater than or equal to zero.  Where pathLenConstraint does
                   not appear, no limit is imposed.

                   So, use a magic value that amounts to infinity
                */
                pathLen = L"ffffffff";
            }

            WriteSimpleElement(L"CA", isCa);
            WriteSimpleElement(L"PathLengthConstraint", pathLen);
        }
        WriteEndElement();
    }

    void WriteGoogleCertTransparancy(const std::vector<std::byte>& extensionBytes)
    {
        GoogleCertTransparency certTransparancy;
        DecodeExtension(certTransparancy, extensionBytes);
        WriteRawExtension(L"GoogleCertTransparency", certTransparancy.GetRawExtensionData());
    }

    void WriteSMIMECapabilities(const std::vector<std::byte>& extensionBytes)
    {
        SmimeCapabilities capabilities;
        DecodeExtension(capabilities, extensionBytes);
        WriteRawExtension(L"SMIMECapabilities", capabilities.GetRawExtensionData());
    }

    void WriteMicrosoftCertSrvCAVersion(const std::vector<std::byte>& extensionBytes)
    {
        MicrosoftCAVersion caVersion;
        DecodeExtension(caVersion, extensionBytes);

        const Integer& version = caVersion.GetVersion();
        std::wstring str;

        ctx::ToString(version, str);
        WriteSimpleElement(L"MicrosoftCAVersion", str);
    }

    void WriteMicrosoftEnrollCertType(const std::vector<std::byte>& extensionBytes)
    {
        MicrosoftEnrollCertType enrollCertType;
        DecodeExtension(enrollCertType, extensionBytes);

        std::wstring str;
        ctx::ToString(enrollCertType.GetCertType(), str);
        WriteSimpleElement(L"MicrosoftEnrollCertType", str);
    }

    void WriteMicrosoftCertSrvPrevHash(const std::vector<std::byte>& extensionBytes)
    {
        MicrosoftPreviousCertHash prevCertHash;
        DecodeExtension(prevCertHash, extensionBytes);

        std::wstring str;
        ctx::ToString(prevCertHash.GetPrevCertHash(), str);
        WriteSimpleElement(L"MicrosoftPreviousCertHash", str);
    }

    void WriteEntrustVersionInfo(const std::vector<std::byte>& extensionBytes)
    {
        EntrustVersion entrustVersion;
        DecodeExtension(entrustVersion, extensionBytes);
        WriteRawExtension(L"EntrustVersion", entrustVersion.GetRawExtensionData());
    }
    
    void WriteIssuerAltName(const std::vector<std::byte>& extensionBytes)
    {
        IssuerAltNames altNames;
        DecodeExtension(altNames, extensionBytes);

        const GeneralNames& names = altNames.GetAltNames();
        WriteStartElement(L"IssuerAltNames");
        WriteGeneralNames(names);
        WriteEndElement();
    }

    void WriteNetscapeCertExt(const std::vector<std::byte>& extensionBytes)
    {
        NetscapeCertExt certExt;
        DecodeExtension(certExt, extensionBytes);
        WriteRawExtension(L"NetscapeCertExt", certExt.GetRawExtensionData());
    }

    void WritePrivateKeyUsagePeriod(const std::vector<std::byte>& extensionBytes)
    {
        PrivateKeyUsagePeriod usagePeriod;
        DecodeExtension(usagePeriod, extensionBytes);
        WriteRawExtension(L"PrivateKeyUsagePeriod", usagePeriod.GetRawExtensionData());
    }

    void WriteKeyUsageRestriction(const std::vector<std::byte>& extensionBytes)
    {
        KeyUsageRestriction usageRestriction;
        DecodeExtension(usageRestriction, extensionBytes);
        WriteRawExtension(L"KeyUsageRestriction", usageRestriction.GetRawExtensionData());
    }

    void WriteFreshestCRL(const std::vector<std::byte>& extensionBytes)
    {
        FreshestCRL freshestCRL;
        DecodeExtension(freshestCRL, extensionBytes);

        const CrlDistributionPoints& distPoints = freshestCRL.GetDistributionPoints();
        const std::vector<DistributionPoint>& distPointVector = distPoints.GetDistributionPoints();

        WriteStartElement(L"FreshestCRL");
        {
            for (const DistributionPoint& point : distPointVector)
            {
                WriteDistributionPoint(point);
            }
        }
        WriteEndElement();
    }

    void WriteUnknownExtension(const std::vector<std::byte>& extensionBytes)
    {
        AnyType any;
        std::wstring str;
		std::wstringstream strstm;

		// We don't understand what this is, and it might not even be ASN.1
		for (size_t pos = 0; pos < extensionBytes.size(); ++pos)
		{
			strstm << std::setfill(L'0') << std::setw(2) << std::hex << (unsigned short)extensionBytes[pos];
		}

		str = strstm.str();
        WriteSimpleElement(L"UnknownExtension", str);
    }

    void WriteExtensionData(const Extension& ext)
    {
        const std::vector<std::byte>& extensionBytes = ext.GetExtensionValue().GetValue();
        const ObjectIdentifier& oid = ext.GetOid();

        switch (OidToExtensionId(oid.GetOidString()))
        {
           case ExtensionId::KeyUsage:
               WriteKeyUsage(extensionBytes);
               return;

           case ExtensionId::ExtendedKeyUsage:
               WriteExtendedKeyUsage(extensionBytes);
               return;

           case ExtensionId::SubjectKeyIdentifier:
               WriteSubjectKeyIdentifier(extensionBytes);
               return;

           case ExtensionId::AuthorityKeyIdentifier:
               WriteAuthorityKeyIdentifier(extensionBytes);
               return;

           case ExtensionId::CRLDistributionPoints:
               WriteCRLDistributionPoints(extensionBytes);
               return;

           case ExtensionId::AuthorityInfoAccess:
               WriteAuthorityInfoAccess(extensionBytes);
               return;

           case ExtensionId::SubjectAltName:
               WriteSubjectAltName(extensionBytes);
               return;

           case ExtensionId::MicrosoftAppCertPolicies:
               WriteMicrosoftAppCertPolicies(extensionBytes);
               return;

           case ExtensionId::CertificatePolicies:
               WriteCertificatePolicies(extensionBytes);
               return;

           case ExtensionId::MicrosoftCertTemplate:
               WriteCertTemplate(extensionBytes);
               return;

           case ExtensionId::AuthorityKeyIdentifierOld:
               WriteAuthorityKeyIdentifierOld(extensionBytes);
               return;

           case ExtensionId::BasicConstraints:
               WriteBasicConstraints(extensionBytes);
               return;

           case ExtensionId::GoogleCertTransparancy:
               WriteGoogleCertTransparancy(extensionBytes);
               return;

           case ExtensionId::SMIMECapabilities:
               WriteSMIMECapabilities(extensionBytes);
               return;

           case ExtensionId::MicrosoftCertSrvCAVersion:
               WriteMicrosoftCertSrvCAVersion(extensionBytes);
               return;

           case ExtensionId::MicrosoftEnrollCertType:
               WriteMicrosoftEnrollCertType(extensionBytes);
               return;

           case ExtensionId::MicrosoftCertSrvPrevHash:
               WriteMicrosoftCertSrvPrevHash(extensionBytes);
               return;

           case ExtensionId::ApplePushDev:
               WriteSimpleElement(L"ApplePushDev", L"");
               return;

           case ExtensionId::ApplePushProd:
               WriteSimpleElement(L"ApplePushProd", L"");
               return;

           case ExtensionId::AppleCustom6:
               WriteSimpleElement(L"AppleCustom6", L"");
               return;

           case ExtensionId::EntrustVersionInfo:
               WriteEntrustVersionInfo(extensionBytes);
               return;

           case ExtensionId::IssuerAltName:
               WriteIssuerAltName(extensionBytes);
               return;

           case ExtensionId::NetscapeCertExt:
               WriteNetscapeCertExt(extensionBytes);
               return;

           case ExtensionId::PrivateKeyUsagePeriod:
               WritePrivateKeyUsagePeriod(extensionBytes);
               return;

           case ExtensionId::KeyUsageRestriction:
               WriteKeyUsageRestriction(extensionBytes);
               return;

           case ExtensionId::FreshestCRL:
               WriteFreshestCRL(extensionBytes);
               return;

           case ExtensionId::Unknown:
               WriteUnknownExtension(extensionBytes);
               return;
        }
    }

    void WriteExtension(const Extension& ext)
    {
        WriteStartElement(L"Extension");
        {
            // Write the OID
            WriteObjectIdentifier(L"ExtensionId", ext.GetOid());

            // And whether it is Critical
            bool fCritical = ext.IsCritical();
            if (fCritical)
            {
                WriteSimpleElement(L"Critical", L"true");
            }

            // Now need to go figure out what this element is
            WriteExtensionData(ext);
        }
        WriteEndElement();
    }

    void WriteExtensions()
    {
        const TBSCertificate& tbsCert = cert.GetTBSCertificate();
        size_t cExtensions = tbsCert.GetExtensionCount();

        if (cExtensions == 0)
            return;

        WriteStartElement(L"Extensions");

        const Extensions extensions = tbsCert.GetExtensions();

        for (size_t i = 0; i < cExtensions; ++i)
        {
            const Extension& ext = extensions.GetExtension(i);
            WriteExtension(ext);
        }

        WriteEndElement();
    }

    void WriteTbsCertificate()
    {
        WriteStartElement(L"TbsCertificate");
        {
            WriteVersion();
            WriteSerialNumber();
            WriteSignature();
            WriteIssuer();
            WriteValidity();
            WriteSubject();
            WriteSubjectPublicKeyInfo();
            WriteIssuerUniqueId();
            WriteSubjectUniqueId();
            WriteExtensions();
        }
        WriteEndElement();
    }

    void WriteSignatureAlgorithm()
    {
        WriteStartElement(L"SignatureAlgorithm");
        WriteAlgorithmIdentifier(cert.GetSignatureAlgorithm());
        WriteEndElement();
    }

    void WriteSignatureValue()
    {
        const BitString& signatureValue = cert.GetSignatureValue();
        std::wstring sigValue;

        ctx::ToString(signatureValue, sigValue);
        WriteStartElement(L"SignatureValue");
        WriteRawElementString(sigValue.c_str());
        WriteEndElement();
    }

private:
    CertXmlWriter() = delete;

    void WriteStartElement(const wchar_t* wzLocalName, const wchar_t* wzPrefix = nullptr, const wchar_t* wzNamespaceUri = nullptr)
    {
        CheckSuccess(pWriter->WriteStartElement(wzPrefix, wzLocalName, wzNamespaceUri));
    }

    void WriteEndElement()
    {
        CheckSuccess(pWriter->WriteEndElement());
    }

    void WriteElementString(const std::string str)
    {
        std::wstring ws = utf8ToUtf16(str);
        WriteElementString(ws.c_str());
    }

	void WriteElementString(const std::wstring str)
	{
		WriteElementString(str.c_str());
	}

	void WriteElementString(const wchar_t* wz)
    {
        CheckSuccess(pWriter->WriteString(wz));
    }

    void WriteRawElementString(const std::wstring str)
    {
        WriteRawElementString(str.c_str());
    }

    void WriteRawElementString(const char* sz)
    {
        std::wstring ws = utf8ToUtf16(sz);
        WriteRawElementString(ws.c_str());
    }

    // Use this to avoid having LF turned into LFLFCR
    void WriteRawElementString(const wchar_t* wz)
    {
        CheckSuccess(pWriter->WriteRaw(wz));
    }

    void WriteSimpleElement(const wchar_t* wzElement, const std::wstring& content)
    {
        WriteStartElement(wzElement);
        WriteElementString(content);
        WriteEndElement();
    }

    void WriteAlgorithmIdentifier(const AlgorithmIdentifier& algId)
    {
        // Assumes an encapsulating element
        ctx::xAlgorithmIdentifier xAlgId;

        xAlgId.Convert(algId);

        WriteObjectIdentifier(L"Algorithm", algId.GetAlgorithm());
        WriteSimpleElement(L"Parameters", xAlgId.params.hexValue);
    }

    void WriteAttributeTypeAndValue(const AttributeTypeAndValue& type)
    {
        std::wstring value;
        ctx::ToString(type.GetValue(), value);

        WriteStartElement(L"AttributeTypeAndValue");
        {
            WriteObjectIdentifier(L"Type", type.GetOid());
            WriteSimpleElement(L"Value", value);
        }
        WriteEndElement();
    }

    void WriteRelativeDistinguishedName(const RelativeDistinguishedName& rdn)
    {
        // Name is an array of RDNs, but a RDN is itself an array of AttributeTypeAndValue
        // though in practice, there is normally one of these
        const std::vector<AttributeTypeAndValue>& attrs = rdn.GetAttributeVector();

        WriteStartElement(L"RelativeDistinguishedName");
        for (const AttributeTypeAndValue& type : attrs)
        {
            WriteAttributeTypeAndValue(type);
        }

        WriteEndElement();
    }

    // Used for subject and issuer
    void WriteNameElement(const wchar_t* wzElementName, const Name& name)
    {
        const RDNSequence& sequence = name.GetRDNSequence();
        const std::vector<RelativeDistinguishedName>& rdnVector = sequence.GetRDNVector();

        WriteStartElement(wzElementName);
        {
            // Now a sequence of RelativeDistinguishedName elements
            for (const RelativeDistinguishedName& rdn : rdnVector)
            {
                WriteRelativeDistinguishedName(rdn);
            }
        }

        WriteEndElement();
    }

    // Use when only ERROR_SUCCESS is OK, S_FALSE is still a failure
    void CheckSuccess(HRESULT hr) 
    { 
        if (hr != ERROR_SUCCESS) 
            throw std::exception(); 
    }

    IXmlWriter * pWriter;
    const Certificate& cert;
};

// Class to wrap a std::vector into an IStream
class IStreamVector : public ISequentialStream
{
public:
    IStreamVector(size_t initSize = 0) : pos(0), data(0), refcount(0) 
    {
        data.reserve(initSize);
    }

    operator ISequentialStream*() { return this; }
    ISequentialStream* operator->() { return this; }

    // IUnknown methods
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void   **ppvObject)
    {
        if (ppvObject == nullptr)
            return E_POINTER;

        if (riid != __uuidof(ISequentialStream))
            return E_NOINTERFACE;

        *ppvObject = static_cast<ISequentialStream*>(this);
        return S_OK;
    }

    // This is intended to be used declared on the stack,
    // and doesn't delete itself until it goes out of scope
    virtual ULONG STDMETHODCALLTYPE AddRef() { return ++refcount; }
    virtual ULONG STDMETHODCALLTYPE Release() { return --refcount; }

    // And the ISequentialStream methods
    virtual HRESULT STDMETHODCALLTYPE Read(void *pv, ULONG cb, ULONG *pcbRead)
    {
        if (pv == nullptr)
            return E_POINTER;

        if (pos >= data.size() || cb == 0)
        {
            if (pcbRead != nullptr)
                *pcbRead = 0;

            return S_FALSE;
        }

        std::byte* pCurrent = &data[pos];
        size_t remaining = data.size() - pos;

        ULONG bytes = cb < remaining ? cb : static_cast<ULONG>(remaining);
        memcpy_s(pv, cb, pCurrent, bytes);
        pos += bytes;

        if (pcbRead != nullptr)
            *pcbRead = bytes;

        return S_OK;
    }

    virtual HRESULT STDMETHODCALLTYPE Write(const void *pv, ULONG cb, ULONG *pcbWritten)
    {
        if (pv == nullptr)
            return E_POINTER;

        if (cb == 0)
        {
            if (pcbWritten != nullptr)
            {
                *pcbWritten = 0;
            }

            return S_FALSE;
        }

        data.insert(data.begin() + pos, static_cast<const std::byte*>(pv), static_cast<const std::byte*>(pv) + cb);
        pos += cb;

        if (pcbWritten != nullptr)
            *pcbWritten = cb;

        return S_OK;
    }

    const std::vector<std::byte>& GetData() const { return data; }
    size_t GetPos() const { return pos; }

private:
    size_t pos;
    std::vector<std::byte> data;
    ULONG refcount;
};

static CoInit init;

bool CertificateToXml(const Certificate& cert, const char* szXmlFile)
{
    ComPtr<IXmlWriter> pWriter;
    IStreamVector stm(1024);

    HRESULT hr = CreateXmlWriter(__uuidof(IXmlWriter), pWriter.PtrAddr(), nullptr);

    if (hr != ERROR_SUCCESS)
    {
        assert(false);
        return false;
    }

    hr = pWriter->SetOutput(stm);
    if (hr != ERROR_SUCCESS)
    {
        assert(false);
        return false;
    }

    // Everything is set up, start writing XML
    CertXmlWriter certWriter(pWriter, cert);

    certWriter.WriteStartDocument();
    certWriter.WriteCertificate();
    pWriter->Flush();

    std::ofstream ostm;
    ostm.open(szXmlFile, std::ios_base::out);

    if (!ostm.is_open())
    {
        assert(false);
        return false;
    }

    const std::vector<std::byte>& stmData = stm.GetData();

    ostm.write(reinterpret_cast<const char*>(&stmData[0]), stm.GetPos());
    ostm.flush();

    return true;
}

