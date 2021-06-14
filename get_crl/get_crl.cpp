#include <CAdESLib/Common.h>
#include <CAdESLib/DerTypes.h>
#include <CAdESLib/CAdES.h>
#include <algorithm>

enum class LoadResult
{
    Success,
    FileOpenFail,
    ParseError,
    DecodeError
};

template <typename T>
LoadResult LoadObjectFromFile(std::string szFile, T &obj)
{
    std::basic_ifstream<std::byte> inFileStream(szFile, std::ios::in | std::ios::binary);

    if (!inFileStream.is_open())
    {
        return LoadResult::FileOpenFail;
    }
    std::vector<std::byte> contents;
    std::copy(std::istreambuf_iterator<std::byte>(inFileStream), std::istreambuf_iterator<std::byte>(), std::back_inserter(contents));
    bool fDecode = false;

    try
    {
        fDecode = obj.Decode(contents);
    }
    catch (...)
    {
        return LoadResult::ParseError;
    }

    if (!fDecode)
        return LoadResult::DecodeError;

    return LoadResult::Success;
}

bool LoadCertificateFromFile(std::string szFile, Certificate &cert)
{
    LoadResult result = LoadObjectFromFile(szFile, cert);

    switch (result)
    {
    case LoadResult::Success:
        return true;

    case LoadResult::DecodeError:
        std::cout << "Malformed certificate: " << szFile << std::endl;
        break;

    case LoadResult::ParseError:
        std::cout << "Malformed certificate - parsing error: " << szFile << std::endl;
        break;

    case LoadResult::FileOpenFail:
        std::cout << "Cannot open input file: " << szFile << std::endl;
        break;
    }

    return false;
}

bool LoadCRLFromFile(std::string szFile, CertificateList &crl)
{
    LoadResult result = LoadObjectFromFile(szFile, crl);

    switch (result)
    {
    case LoadResult::Success:
        return true;

    case LoadResult::DecodeError:
        std::cout << "Malformed CRL: " << szFile << std::endl;
        break;

    case LoadResult::ParseError:
        std::cout << "Malformed CRL - parsing error: " << szFile << std::endl;
        break;

    case LoadResult::FileOpenFail:
        std::cout << "Cannot open input file: " << szFile << std::endl;
        break;
    }

    return false;
}

template <typename T>
void DecodeExtension(T &t, const std::vector<std::byte> &extensionBytes)
{
    size_t cbExtension = extensionBytes.size();

    if (cbExtension > 0 && t.Decode(extensionBytes))
        return;

    throw std::exception(); // Malformed extension
}

void WriteGeneralName(const GeneralName &name)
{
    GeneralNameType type = name.GetType();

#pragma warning(disable : 4061)
    switch (type)
    {
    case GeneralNameType::uniformResourceIdentifier:
        break;

    case GeneralNameType::OtherName:
    case GeneralNameType::rfc822Name:
    case GeneralNameType::dNSName:
    case GeneralNameType::x400Address:
    case GeneralNameType::directoryName:
    case GeneralNameType::ediPartyName:
    case GeneralNameType::iPAddress:
    case GeneralNameType::registeredID:
    default:
        return;
    }
#pragma warning(default : 4061)

    IA5String uri;
    std::string str;

    name.GetURI(uri);
    std::stringstream strstm;
    strstm << uri;
    str = strstm.str();

    std::cout << "CRL URI: " << str << std::endl;
}

void WriteDistributionPoint(const DistributionPoint &point)
{
    if (point.HasDistributionPoint())
    {
        const DistributionPointName &distName = point.GetDistributionPoint();

        if (distName.HasFullName())
        {
            const GeneralNames &fullName = distName.GetFullName();

            for (const GeneralName &name : fullName.GetNames())
            {
                WriteGeneralName(name);
            }
        }

        // It is atypical for the distribution point name to be
        // relative to the CRL issuer, and if we encountered one, not sure how to
        // download the CRL
        // if (distName.HasNameRelativeToCRLIssuer())
    }

    // Ignore reason flags, not typically present
    // if (point.HasReasonFlags())

    // The CRL issuer is in the case where the cert issuer and the CRL issuer
    // are not the same. Ignore this for now
    // if (point.HasCRLIssuer())
}

void WriteCRLDistributionPoints(const std::vector<std::byte> &extensionBytes)
{
    CrlDistributionPoints distPoints;
    DecodeExtension(distPoints, extensionBytes);

    const std::vector<DistributionPoint> &distPointVector = distPoints.GetDistributionPoints();

    for (const DistributionPoint &point : distPointVector)
    {
        WriteDistributionPoint(point);
    }
}

struct crl_options
{
    bool common_name;
    bool revoked;
};

void PrintCRL(const CertificateList &crl, const crl_options &opts)
{
    // Not interested in the signature or algorithm for the moment
    const TBSCertList &tbs_cert_list = crl.tbsCertList;

    const Integer &version = tbs_cert_list.version;
    uint32_t ulversion = 0;
    if (!version.GetValue(ulversion))
    {
        std::cout << "Version: v1" << std::endl;
    }
    else
    {
        if (ulversion == 1)
            std::cout << "Version: v2" << std::endl;
        else
            std::cout << "Version: Unknown - " << ulversion << std::endl;
    }

    const AlgorithmIdentifier &alg_id = tbs_cert_list.signature;
    std::cout << "Signature Alg: " << alg_id.AlgorithmLabel() << std::endl;

    // Issuer
    std::string issuer;
    tbs_cert_list.issuer.ToString(issuer);
    std::cout << "Issuer: " << issuer << std::endl;

    std::cout << "This Update: " << tbs_cert_list.thisUpdate.GetValue() << std::endl;
    std::cout << "Next Update: " << tbs_cert_list.nextUpdate.GetValue() << std::endl;

    const Extensions &crlExtensions = tbs_cert_list.crlExtensions.GetInnerType();

    for (size_t i = 0; i < crlExtensions.Count(); ++i)
    {
        const Extension &ext = crlExtensions.GetExtension(i);
        const auto label = ext.ExtensionIdLabel();

        if (!label.empty())
        {
            const std::vector<std::byte> &extensionBytes = ext.GetExtensionValue().GetValue();

            if (label == "authorityKeyIdentifier")
            {
                AuthorityKeyIdentifier aki;
                DecodeExtension(aki, extensionBytes);

                if (aki.HasKeyIdentifier())
                {
                    const OctetString &keyIdentifier = aki.GetKeyIdentifier();
                    std::cout << "KeyIdentifier: " << keyIdentifier << std::endl;
                }
                continue;
            }
            else if (label == "cRLNumber")
            {
                Integer number;
                DecodeExtension(number, extensionBytes);
                std::cout << "CRL Number: " << number << std::endl;
                continue;
            }
            else if (label == "issuingDistributionPoint")
            {
                IssuingDistributionPoint distPoint;
                DecodeExtension(distPoint, extensionBytes);
            }
            else if (label == "microsoft_certsrvCAVersion")
            {
                // Ignore
                continue;
            }
            else if (label == "microsoft_certsrvnNextPublish")
            {
                // Ignore
                continue;
            }
            else
            {
                std::cout << "Entry Extension Label: " << label << std::endl;
                std::cout << "Entry Extension Oid: " << ext.ExtensionIdOidString() << std::endl;
            }
        }
        else
        {
            const ObjectIdentifier &oid = ext.GetOid();
            std::string oid_string;
            oid.ToString(oid_string);

            std::cout << "Extension Label: Unknown" << std::endl;
            std::cout << "Extension Oid: " << oid_string << std::endl;
        }
    }

    if (opts.revoked == false)
        return;

    // Now the individual records
    const RevokedCertificates &revoked_certs = tbs_cert_list.revokedCertificates;

    for (size_t i = 0; i < revoked_certs.GetCount(); ++i)
    {
        const RevocationEntry &entry = revoked_certs.GetRevocationEntry(i);
        const Extensions &entry_extensions = entry.crlEntryExtensions;

        for (size_t j = 0; j < entry_extensions.Count(); ++j)
        {
            const Extension &ext = entry_extensions.GetExtension(j);
            auto label = ext.ExtensionIdLabel();

            if (!label.empty())
            {
                std::cout << "Entry Extension Label: " << label << std::endl;
                std::cout << "Entry Extension Oid: " << ext.ExtensionIdOidString() << std::endl;
            }
            else
            {
                const ObjectIdentifier &oid = ext.GetOid();
                std::string oid_string;
                oid.ToString(oid_string);

                std::cout << "Entry Extension Label: Unknown" << std::endl;
                std::cout << "Entry Extension Oid: " << oid_string << std::endl;
            }
        }
    }
}

int32_t main(int32_t argc, char *argv[])
{
    std::string szFile;
    bool is_cert = true;
    crl_options opts = {};
    bool badarg = false;

    if (argc > 1)
    {
        szFile = argv[argc - 1];
    }

    for (int32_t i = 1; i < argc - 1; ++i)
    {
        if (strcmp("-crl", argv[i]) == 0)
        {
            is_cert = false;
            continue;
        }
        else if (strcmp("-cn", argv[i]) == 0)
        {
            opts.common_name = true;
        }
        else if (strcmp("-revoked", argv[i]) == 0)
        {
            opts.revoked = true;
        }
        else
        {
            badarg = true;
        }
    }

    if (argc == 1 || badarg)
    {
        std::cout << "Usage is get_crl [path to cert]" << std::endl;
        std::cout << "Usage is get_crl -crl [path to crl]" << std::endl;
        std::cout << "Certificate must be DER encoded, PEM not supported yet" << std::endl;
        return -1;
    }

    if (is_cert)
    {
        Certificate cert;

        if (LoadCertificateFromFile(szFile, cert))
        {
            const TBSCertificate &tbs_cert = cert.GetTBSCertificate();
            size_t extension_count = tbs_cert.GetExtensionCount();

            for (size_t i = 0; i < extension_count; ++i)
            {
                const Extension &ext = tbs_cert.GetExtension(i);

                if (id_ce_cRLDistributionPoints == ext.ExtensionIdOidString())
                {
                    const std::vector<std::byte> &extensionBytes = ext.GetExtensionValue().GetValue();
                    WriteCRLDistributionPoints(extensionBytes);
                }
            }
        }
        else
        {
            std::cout << "Malformed input certificate" << std::endl;
        }
    }
    else
    {
        CertificateList crl;
        if (LoadCRLFromFile(szFile, crl))
        {
            PrintCRL(crl, opts);
        }
    }

    return 0;
}