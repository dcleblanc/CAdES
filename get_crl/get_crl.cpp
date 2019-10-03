#include "../CAdESLib/Common.h"

bool LoadCertificateFromFile(const char* szFile, Certificate& cert)
{
	std::ifstream stm(szFile, std::ios::in | std::ios::binary);
	std::vector<unsigned char> contents((std::istreambuf_iterator<char>(stm)), std::istreambuf_iterator<char>());

	if (!stm.is_open())
	{
		return false;
	}

	size_t cbUsed = 0;
	bool fDecode = false;

	try
	{
		fDecode = cert.Decode(&contents[0], contents.size(), cbUsed);
	}
	catch (...)
	{
		std::cout << "Malformed certificate: " << szFile << std::endl;
		return false;
	}

	if (!fDecode || cbUsed != contents.size())
		return false;

	return true;
}

template <typename T>
void DecodeExtension(T& t, const std::vector<unsigned char>& extensionBytes)
{
    size_t cbExtension = extensionBytes.size();
    size_t cbUsed = 0;

    if (cbExtension > 0 && t.Decode(&extensionBytes[0], cbExtension, cbUsed) && cbUsed == cbExtension)
        return;

    throw std::exception(); // Malformed extension
}

void WriteGeneralName(const GeneralName& name)
{
    GeneralNameType type = name.GetType();

    switch(type)
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

    IA5String uri;
    std::string str;

    name.GetURI(uri);
    std::stringstream strstm;
    strstm << uri;
    str = strstm.str();

    std::cout << "CRL URI: " << str << std::endl;
}

void WriteDistributionPoint(const DistributionPoint& point)
{
        if (point.HasDistributionPoint())
        {
            const DistributionPointName& distName = point.GetDistributionPoint();

            if (distName.HasFullName())
            {
                const GeneralNames& fullName = distName.GetFullName();

                for (const GeneralName& name : fullName.GetNames())
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

void WriteCRLDistributionPoints(const std::vector<unsigned char>& extensionBytes)
{
    CrlDistributionPoints distPoints;
    DecodeExtension(distPoints, extensionBytes);

    const std::vector<DistributionPoint>& distPointVector = distPoints.GetDistributionPoints();

    for (const DistributionPoint& point : distPointVector)
    {
        WriteDistributionPoint(point);
    }
}

int main(int argc, char* argv[])
{
    Certificate cert;

    if(argc != 2)
    {
        std::cout << "Usage is get_crl [path to cert]" << std::endl;
        std::cout << "Certificate must be DER encoded, PEM not supported yet" << std::endl;
        return -1;
    }

    if(LoadCertificateFromFile(argv[1], cert))
    {
        const TBSCertificate& tbs_cert = cert.GetTBSCertificate();
        size_t extension_count = tbs_cert.GetExtensionCount();

        for( size_t i = 0; i < extension_count; ++i )
        {
            const Extension& ext = tbs_cert.GetExtension(i);

            if( strcmp(id_ce_cRLDistributionPoints, ext.ExtensionIdOidString()) == 0 )
            {
                const std::vector<unsigned char>& extensionBytes = ext.GetExtensionValue().GetValue();
                WriteCRLDistributionPoints(extensionBytes);
            }
        }
    }
    else
    {
        std::cout << "Malformed input certificate" << std::endl;
    }
    

    return 0;
}