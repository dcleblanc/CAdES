#include "Common.h"
#include <stdio.h>
#include <fstream>
#include <sstream>

#ifdef WIN32
void OidTest();
#else
void OidTest() {}
#endif // WIN32

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

	unsigned char buf[sizeof(unsigned long long)];
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
			f = DecodeSize(buf, sizeof(buf), result, cbRead);

			if(!f || result != values[i].value || cbRead != cbUsed)
				throw std::exception("DecodeSize failed");
		}
	}

	// This should also fail
	memset(buf, 0xff, sizeof(buf));
	f = DecodeSize(buf, sizeof(buf), result, cbRead);

	if (f == true)
		throw std::exception("DecodeSize failed");

}

bool ParseDer(const unsigned char* pIn, size_t cbIn)
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

		if (!DecodeSize(pIn + pos + 1, cbIn - (pos + 1), size, cbSize) || cbIn - pos + 1 < size)
			throw std::exception("ruh, roh");

		pos += cbSize + 1;

		if (type.constructed)
		{
			if(!ParseDer(pIn + pos, static_cast<size_t>(size)))
				throw std::exception("ruh, roh");
		}

		pos += static_cast<size_t>(size);
	}

	return true;
}

void ParseTest()
{
	std::ifstream stm("test.cer", std::ios::in | std::ios::binary);
	std::vector<unsigned char> contents((std::istreambuf_iterator<char>(stm)), std::istreambuf_iterator<char>());

	if (!stm.is_open())
	{
		printf("Doh!\n");
		return;
	}

	printf("Opened file\n");
//	DebugDer(&contents[0], contents.size());

	Certificate cert;

	size_t cbUsed = 0;
	if (cert.Decode(&contents[0], contents.size(), cbUsed))
		printf("Yay!\n");
	
	return;

}

int main(int argc, char* argv[])
{
	argc; argv;

	ParseTest();
	/*
	OidTest();
	EncodeSizeTest();
	*/

	return 0;
}