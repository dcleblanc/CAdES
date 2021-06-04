#include "../CAdESLib/Common.h"
#include "CertToXml.h"

bool LoadCertificateFromFile(const char* szFile, Certificate& cert)
{
	std::ifstream stm(szFile, std::ios::in | std::ios::binary);
	std::vector<std::byte> contents((std::istreambuf_iterator<char>(stm)), std::istreambuf_iterator<char>());

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

	cert.SetFileName(szFile);
	HashVectorSha1(contents, cert.GetThumbprint());
	HashVectorSha256(contents, cert.GetThumbprint256());

	return true;
}

void DumpCertProperties(const char* szFile)
{
	Certificate cert;
	if (!LoadCertificateFromFile(szFile, cert))
	{
		std::cout << "LoadCertificateFromFile failed: " << szFile << std::endl;
	}

	std::string xmlFile = szFile;
	xmlFile += ".xml";

	CertificateToXml(cert, xmlFile.c_str());

	return;
}

void PrintOids();
void TestOidTable();

int32_t DumpXML(const char* szFile)
{
	int32_t ret;
	try
	{
		DumpCertProperties(szFile);
		ret = 0;
	}
	catch (...)
	{
		// TODO - more about the exception here
		std::cout << "Exception parsing: " << szFile << std::endl;
		ret = -1;
	}
	return ret;
}

int32_t main(int32_t argc, char* argv[])
{
	const char* szFile = nullptr;
	bool fMultiPass = false;

	switch (argc)
	{
	case 2:
		szFile = argv[argc - 1];
		break;
	case 3:
		if (strcmp(argv[1], "-f") == 0)
		{
			szFile = argv[argc - 1];
			fMultiPass = true;
			break;
		}
		__fallthrough;
	case 1:
	default:
		std::cout << "Usage is " << argv[0] << "[Certificate file]" << std::endl;
		std::cout << "Or -f [file with list of certs" << std::endl;
		return -1;
	}

	int32_t ret = 0;

	if (fMultiPass)
	{
		std::vector<std::string> fileList;
		std::ifstream in(szFile);

		if (!in)
		{
			std::cout << "Cannot open certificate file " << szFile << std::endl;
			return -1;
		}

		std::string tmp;
		while (std::getline(in, tmp))
		{
			fileList.push_back(tmp);
		}

		for (const std::string& s : fileList)
		{
			ret = DumpXML(s.c_str());
		}
	}
	else
	{
		ret = DumpXML(szFile);
	}

	return ret;
}