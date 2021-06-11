#pragma once

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <span>

// Core CMS Signature attributes
class ContentTypeAttribute
{
public:
	ContentTypeAttribute() : attr(id_contentType) {}

	void ContentType(std::string oid);

private:
	Attribute attr;
};

class SigningTimeAttribute
{
public:
	SigningTimeAttribute() : attr(id_signingTime) {}

	void SetTime();

private:
	Attribute attr;
};

class MessageDigestAttribute
{
public:
	MessageDigestAttribute() : attr(id_messageDigest) {}

	void SetDigest(std::span<const std::byte> digest);

private:
	Attribute attr;
};

class CounterSignatureAttribute
{
public:
	CounterSignatureAttribute() : attr(id_countersignature) {}

	void SetSignedData(const SignedData& signedData);

private:
	Attribute attr;
};

/* CAdES specific attributes*/
class ESSSigningCertificateAttribute
{
	// ESS signing-certificate (sha1) OR ESS signing-certificate-v2 (sha2)
	// Correctly initializing this class may involve submitting multiple ESSCertIDv2
	// objects, so we need to keep a local copy of the internal SigningCertificateV2
	// class

public:
	void AddSigningCert(const ESSCertIDv2& certID)
	{
		signingCert.AddSigningCert(certID);
	}

	void AddPolicy(const PolicyInformation& policy)
	{
		signingCert.AddPolicyInformation(policy);
	}

private:
	SigningCertificateV2 signingCert;
	Attribute attr;
};

class CMSSignature
{
public:

private:
	// Mandatory signed attributes for CAdES-BES
	ContentTypeAttribute contentType;
	MessageDigestAttribute messageDigest;
	ESSSigningCertificateAttribute essSigningCert;
};
