// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef _WIN32

#include <Windows.h>
#include "../CAdESLib/Common.h"
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "Crypt32.lib")

/*
	Use this file to test encoding and decoding interop with the Windows APIs.
	To the extent that we can find other libraries to use to test with, we should.
*/

// CRYPT_ASN_ENCODING, X509_ASN_ENCODING, and PKCS_7_ASN_ENCODING
const DWORD encodingType = X509_ASN_ENCODING;

/*
	 Primary object types - 
	 X509_OCTET_STRING
	 X509_UNICODE_NAME
	 PKCS_UTC_TIME
*/

bool DecodeObject(LPCSTR lpszStructType, const unsigned char* encoded, unsigned long cbEncoded, void* out, unsigned long& cbOut)
{
	const DWORD flags = 0;
	return !!CryptDecodeObject(encodingType, lpszStructType, encoded, cbEncoded, flags, out, &cbOut);
}

bool EncodeObject(LPCSTR lpszStructType, const void* in, BYTE* out, unsigned long& cbEncoded)
{
	return !!CryptEncodeObjectEx(encodingType, lpszStructType, in, 0, nullptr, out, &cbEncoded);
}

bool DecodeObjectIdentifier(const unsigned char* encoded, unsigned long cbEncoded, std::string& out)
{
	char buf[1024];
	unsigned long cbOut = sizeof(buf);

	if (!DecodeObject(X509_OBJECT_IDENTIFIER, encoded, cbEncoded, buf, cbOut))
		return false;

	out = buf;
	return true;
}

bool EncodeObjectIdentifier(const char** in, unsigned char* out, unsigned long& cbOut)
{
	return EncodeObject(X509_OBJECT_IDENTIFIER, in, out, cbOut);
}

void OidTest()
{
	
	const char* testOids[] =
	{
		"1.3.6.1.8.2.19", // 0x06, 0x06, 0x2b, 0x06, 0x01, 0x08, 0x02, 0x13
		"2.51.1.12",      // 0x06, 0x04, 0x81, 0x03, 0x01, 0x0c
		"2.999",
		"1.2.840.113549.1.9.16.5"
	};

	for (unsigned int i = 0; i < _countof(testOids); ++i)
	{
		unsigned char buf[256];
		unsigned char buf2[256];
		unsigned long cbOut = sizeof(buf);
		size_t cbUsed = 0;
		std::string test;

		EncodeObjectIdentifier(&(testOids[i]), buf, cbOut);

		ObjectIdentifier oi;
		oi.SetValue(testOids[i]);
		oi.Encode(buf2, sizeof(buf2), cbUsed);

		if (cbOut != cbUsed || memcmp(buf, buf2, cbOut) != 0)
			throw std::exception("OID encoding failed");

		// Now test the decode and ToString 
		ObjectIdentifier oiOut;
		size_t cbRead = 0;
		std::string s;

		oiOut.Decode(buf2, cbUsed, cbRead);
		oiOut.ToString(s);

		if(s != testOids[i])
			throw std::exception("OID decoding failed");

	}
}

#endif // WIN32
