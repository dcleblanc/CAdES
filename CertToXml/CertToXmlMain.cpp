#include "../CAdESLib/Common.h"
#include "CertToXml.h"

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

int main(int argc, char* argv[])
{
	const char* szFile = nullptr;

	if (argc >= 2)
	{
		szFile = argv[argc - 1];
	}
	else
	{
		std::cout << "Usage is " << argv[0] << "[Certificate file]" << std::endl;
		return -1;
	}

	int ret;
	try
	{
		DumpCertProperties(szFile);
		ret = 0;
	}
	catch (...)
	{
		// TODO - more about the exception here
		ret = -1;
	}

	return ret;
}