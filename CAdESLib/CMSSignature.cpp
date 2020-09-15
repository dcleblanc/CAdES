// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"

void ContentTypeAttribute::ContentType(const char* oid)
{
	ObjectIdentifier oi(oid);
	AnyType any;
	any.SetValue(oi);
	attr.AddAttributeValue(any);
}

void SigningTimeAttribute::SetTime()
{
	Time now;
	now.SetValue();

	AnyType any;
	any.SetValue(now);
	attr.AddAttributeValue(any);
}

void MessageDigestAttribute::SetDigest(const uint8_t* pDigest, size_t cbDigest)
{
	OctetString os;
	os.SetValue(pDigest, cbDigest);

	AnyType any;
	any.SetValue(os);
	attr.AddAttributeValue(any);
}

void CounterSignatureAttribute::SetSignedData(const SignedData & /*signedData*/)
{

	// Not implemented
	throw std::bad_function_call();
	/*
	size_t cbUsed = 0;
	TBD, SignedData::EncodedSize not coded yet
	size_t cbBuffer = signedData.EncodedSize();
	std::vector<uint8_t> buffer(cbBuffer);

	if (!Encode(os, &buffer[0], buffer.size(), cbUsed))
		throw std::exception("Error in Encode");
	
	AnyType any;
	any.SetEncodedValue(buffer);
	attr.attrValues.push_back(any);
	*/
}