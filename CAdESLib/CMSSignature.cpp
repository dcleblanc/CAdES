// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "CMSSignature.h"

#include "Common.h"
#include "DerTypes.h"
#include "CAdES.h"

void ContentTypeAttribute::ContentType(std::string oid)
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

void MessageDigestAttribute::SetDigest(std::span<const std::byte> digest)
{
	OctetString os;
	os.SetValue(digest);

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
	std::vector<std::byte> buffer(cbBuffer);

	if (!Encode(os, &buffer[0], buffer.size(), cbUsed))
		throw std::exception("Error in Encode");
	
	AnyType any;
	any.SetEncodedValue(buffer);
	attr.attrValues.push_back(any);
	*/
}