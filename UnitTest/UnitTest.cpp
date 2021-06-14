// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <CAdESLib/Common.h>
#include <CAdESLib/DerTypes.h>
#include <CAdESLib/CAdES.h>
#include <CAdESLib/DerDecode.h>
#include <stdio.h>
#include <fstream>
#include <sstream>

#ifdef _WIN32
void OidTest();
#else
void OidTest() {}
#endif // WIN32

struct options
{
	options() : dumpDebug(false), parseTest(false), oidTest(false), encodeSizeTest(false)
	{}

	bool dumpDebug;
	bool parseTest;
	bool oidTest;
	bool encodeSizeTest;
};

options opts;

void InstantiateObjects()
{
	EncapsulatedContentInfo a1;
	Attribute a2;
	RelativeDistinguishedName a3;
	RDNSequence a4;

	IssuerAndSerialNumber a5;
	SignerIdentifier a6;
	Extension a7;
	AlgorithmIdentifier a8;
	SignerInfo a9;
	OtherCertificateFormat a10;
	SubjectPublicKeyInfo a11;
	TBSCertificate a12;
	Certificate a13;
	DirectoryString a14;
	EDIPartyName a15;
	GeneralName a16;
	IssuerSerial a17;
	ObjectDigestInfo a18;
	Holder a19;
	AttCertValidityPeriod a20;
	V2Form a21;
	AttributeCertificateInfo a22;
	AttributeCertificate a23;
	CertificateChoices a24;
	RevocationEntry a25;
	TBSCertList a26;
	CertificateList a27;
	OtherRevocationInfoFormat a28;
	RevocationInfoChoice a29;
	SignedData a30;
	ContentInfo a31;
	DisplayText a32;
	NoticeReference a33;
	UserNotice a34;
	PolicyQualifierInfo a35;
	PolicyInformation a36;
	ESSCertID a37;
	SigningCertificate a38;
	ESSCertIDv2 a39;
	SigningCertificateV2 a40;
	OtherHashAlgAndValue a41;
	SigPolicyQualifierInfo a42;
	SignaturePolicyId a43;
	SPUserNotice a44;
	CommitmentTypeQualifier a45;
	CommitmentTypeIndication a46;
	SignerLocation a47;
	SignerAttribute a48;
	MessageImprint a49;
	TimeStampReq a50;
	PKIStatusInfo a51;
	TimeStampResp a52;
	Accuracy a53;
	TSTInfo a54;
	OtherCertId a55;
	CrlIdentifier a56;
	CrlValidatedID a57;
	ResponderID a58;
	OcspIdentifier a59;
	OcspResponsesID a60;
	OcspListID a61;
	OtherRevRefs a62;
	CrlOcspRef a63;
	OtherRevVals a64;
	RevokedInfo a65;
	CertStatus a66;
	CertID a67;
	SingleResponse a68;
	ResponseData a69;
	BasicOCSPResponse a70;
	RevocationValues a71;
	AnyType a73;
	Boolean a74;
	Integer a75;
	BitString a76;
	OctetString a77;
	Enumerated a78;
	ObjectIdentifier a79;
	UTCTime a80;
	GeneralizedTime a81;
	Time a82;
	IA5String a83;
	GeneralString a84;
	PrintableString a85;
	T61String a86;
	UTF8String a87;
	VisibleString a88;
	UniversalString a89;
	BMPString a90;
	Null a91;
	GeneralNames a92;
	KeyUsage a93;
	ExtendedKeyUsage a94;
	SubjectKeyIdentifier a95;
	DistributionPoint a96;
	CrlDistributionPoints a97;
	AuthorityKeyIdentifier a98;
	AccessDescription a99;
	AuthorityInfoAccess a100;
	KeyPurposes a101;
	CertTemplate a102;
	BasicConstraints a103;
	MicrosoftCAVersion a104;
	MicrosoftEnrollCertType a105;
	MicrosoftPreviousCertHash a106;
	ApplePushDev a107;
	ApplePushProd a108;
	AppleCustom6 a109;
	IssuerAltNames a110;
	KeyUsageRestriction a111;
	FreshestCRL a112;
	PolicyInformation a113;
}

struct TestValue
{
	size_t value;
	bool result;
};

void EncodeSizeTest()
{
	TestValue values[] =
	{
		{0x23, true},
		{0xffff, true },
		{~static_cast<size_t>(0), false}/*,
		{0xffffffffffffff, true},
		{ 0xffffffffffffff + 1, false }*/
	};

	std::byte buf[sizeof(uint64_t)];
	size_t cbUsed;
	size_t result;
	size_t cbRead;
	bool f;

	for (unsigned i = 0; i < _countof(values); ++i)
	{
		f = EncodeSize(values[i].value, buf, sizeof(buf), cbUsed);

		if (f != values[i].result)
			throw std::exception("EncodeSize failed");

		if (f == true)
		{
			f = DerDecode::DecodeSize(buf, sizeof(buf), result, cbRead);

			if (!f || result != values[i].value || cbRead != cbUsed)
				throw std::exception("DecodeSize failed");
		}
	}

	// This should also fail
	memset(buf, 0xff, sizeof(buf));
	f = DerDecode::DecodeSize(buf, sizeof(buf), result, cbRead);

	if (f == true)
		throw std::exception("DecodeSize failed");

}

bool ParseDer(const std::byte* pIn, size_t cbIn)
{
	size_t pos = 0;
	while (pos < cbIn)
	{
		DerTypeContainer type(pIn[pos]);
		size_t cbSize = 0;
		size_t size = 0;

		// Some diagnostics
		if (type._class != DerClass::Universal)
		{
			printf("Unknown type - %x\n", pIn[pos]);
		}

		if (!DerDecode::DecodeSize(pIn + pos + 1, cbIn - (pos + 1), size, cbSize) || cbIn - pos + 1 < size)
			throw std::exception("ruh, roh");

		pos += cbSize + 1;

		if (type.constructed)
		{
			if (!ParseDer(pIn + pos, static_cast<size_t>(size)))
				throw std::exception("ruh, roh");
		}

		pos += static_cast<size_t>(size);
	}

	return true;
}

void DebugDump(const char* szFile, const std::byte* pData, size_t cbData)
{
	std::string dbgFile(szFile);
	dbgFile += ".dmp";

	std::ofstream ostm(dbgFile.c_str());

	if (ostm.is_open())
	{
		try { DebugDer(ostm, pData, cbData); }
		catch (std::exception& oops)
		{
			std::cout << "Cannot create debug file for: " << szFile << " error= " << oops.what() << std::endl;
		}

		std::cout << "Debug file created: " << dbgFile << std::endl;
	}
	else
	{
		std::cout << "Cannot open dmp file: " << dbgFile << std::endl;
	}
}

void ParseTest(const char * szFile)
{
	std::ifstream stm(szFile, std::ios::in | std::ios::binary);
	std::vector<std::byte> contents((std::istreambuf_iterator<char>(stm)), std::istreambuf_iterator<char>());

	if (!stm.is_open())
	{
		std::cout << "FILE_NOT_FOUND: " << szFile << std::endl;
		return;
	}

	Certificate cert;

	size_t cbUsed = 0;
	size_t cbOut = 0;

	bool fEncode = false;
	bool fDecode = false;
	size_t cbBuffer = (contents.size() + (4096 - 1)) & ~(4096 - 1);
	std::vector<std::byte> outBuf(cbBuffer);

	try
	{
		fDecode = cert.Decode(&contents[0], contents.size(), cbUsed);
		if (fDecode)
		{
			std::cout << "SUCCESS: " << szFile << std::endl;
		}
		else
		{
			std::cout << "Decode failed: " << szFile << std::endl;
			DebugDump(szFile, &contents[0], contents.size());
			return;
		}

		// Now let's see if we can round-trip the file
		try
		{
			cert.Encode(&outBuf[0], outBuf.size(), cbOut);
		}
		catch (...)
		{
			std::cout << "Exception in Encode" << std::endl;
		}

		if (cbUsed != cbOut)
		{
			std::cout << "Output size mismatch" << std::endl;

			if (opts.dumpDebug)
				DebugDump(szFile, &contents[0], contents.size());
		}
		else
		{
			fEncode = true;
		}

		// Now let's compare the two, ensure that they match
		// For convenience - 
		for (size_t pos = 0; pos < contents.size(); ++pos)
		{
			if (contents[pos] != outBuf[pos])
			{
				std::cout << "Mismatch at offset " << pos << " Input = " << (int32_t)contents[pos] << " Output = " << (int32_t)outBuf[pos] << std::endl;
				fEncode = false;
			}
		}
	}
	catch (std::exception& doh)
	{
		std::cout << doh.what() << std::endl;
		if (fDecode)
			fEncode = false;
	}

	if (fDecode && !fEncode)
	{
		std::cout << "FAILED: " << szFile << std::endl;

		if (!fEncode)
		{
			std::string szEncode(szFile);
			szEncode += "_encode";
			DebugDump(szEncode.c_str(), &outBuf[0], cbOut);
		}
	}

	return;

}

void PrintOids();
void TestOidTable();

int32_t main(int32_t argc, char* argv[])
{
	bool fPrintUsage = false;
	const char* szFile = nullptr;

	// Last argument, if present, has to be the file name
	for (int32_t i = 1; i < argc - 1; ++i)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'd':
				opts.dumpDebug = true;
				break;
			case 'p':
				opts.parseTest = true;
				break;
			case 'o':
				opts.oidTest = true;
				break;
			case 'e':
				opts.encodeSizeTest = true;
				break;
			default:
				std::cout << argv[i] << " unsupported option" << std::endl;
				fPrintUsage = true;
				break;
			}
		}
	}

	if (argc >= 2 && opts.parseTest)
	{
		szFile = argv[argc - 1];
	}
	else
	{
		std::cout << "Usage is " << argv[0] << "[options] [Certificate file]" << std::endl;
		std::cout << "Currently supported options are:" << std::endl;
		std::cout << "\t-d - Create debug dump of input file" << std::endl;
		std::cout << "\t-p - Run parse test on input file" << std::endl;
		std::cout << "\t-o - Run OID test" << std::endl;
		std::cout << "\t-e - Run size encoding test" << std::endl;
		return -1;
	}

	// TODO - make these switches
	// Ensure that the core elements of the library actually function
	// PrintOids is needed if you need to regenerate the OID table else it is a noop
	// PrintOids();
	// TestOidTable();

	if (szFile != nullptr && opts.parseTest)
		ParseTest(szFile);

	if(opts.oidTest)
		OidTest();

	if(opts.encodeSizeTest)
		EncodeSizeTest();

	return 0;
}