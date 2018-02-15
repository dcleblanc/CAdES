// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"

const char* hashOids[] =
{
	id_md2,
	id_md5,
	id_sha1,
	id_sha224,
	id_sha256,
	id_sha384,
	id_sha512
};

AlgorithmIdentifier::AlgorithmIdentifier(HashAlgorithm alg) : algorithm(hashOids[static_cast<ptrdiff_t>(alg)])
{
	parameters.SetNull();
}

void Accuracy::Encode(unsigned char* pOut, size_t cbOut, size_t& cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if(cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	seconds.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	millis.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	micros.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool Accuracy::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!seconds.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!millis.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!micros.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void AlgorithmIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	algorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	parameters.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool AlgorithmIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!algorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!parameters.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void Attribute::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;
	
	attrType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(attrValues, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool Attribute::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!attrType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;

	pIn += offset;
	cbIn -= offset;

	if (DecodeSet(pIn, cbIn, cbUsed, attrValues))
	{
		cbUsed = cbUsed + offset;
		return true;
	}

	cbUsed = 0;
	return false;
}

void EncapsulatedContentInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	eContentType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	eContent.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool EncapsulatedContentInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!eContentType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!eContent.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void IssuerSerial::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	issuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serial.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerUID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	cbUsed = cbNeeded;
}

bool IssuerSerial::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!issuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!serial.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerUID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void ObjectDigestInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	digestedObjectType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherObjectTypeID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	digestAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	objectDigest.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool ObjectDigestInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!digestedObjectType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherObjectTypeID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!digestAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!objectDigest.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void Holder::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	baseCertificateID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	entityName.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	objectDigestInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool Holder::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!baseCertificateID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!entityName.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!objectDigestInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherHashAlgAndValue::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	hashAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	hashValue.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OtherHashAlgAndValue::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!hashAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!hashValue.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void V2Form::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	issuerName.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	baseCertificateID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	objectDigestInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool V2Form::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!issuerName.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!baseCertificateID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!objectDigestInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void AttCertValidityPeriod::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	notBeforeTime.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	notAfterTime.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool AttCertValidityPeriod::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!notBeforeTime.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!notAfterTime.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void AttributeCertificateInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	holder.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signature.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serialNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	attrCertValidityPeriod.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(attributes, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerUniqueID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	extensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool AttributeCertificateInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!holder.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!holder.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signature.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!serialNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!attrCertValidityPeriod.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn, cbIn, cbUsed, attributes))
		return false;

	offset += cbUsed;
	if (!issuerUniqueID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!extensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void AttributeCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	acinfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureValue.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool AttributeCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!acinfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureValue.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CertID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	hashAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerNameHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerKeyHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serialNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CertID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!hashAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerNameHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerKeyHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!serialNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void RevokedInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	revocationTime.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	revocationReason.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool RevokedInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!revocationTime.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!revocationReason.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SingleResponse::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	certID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	certStatus.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	thisUpdate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	nextUpdate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	singleExtensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SingleResponse::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!certID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!certStatus.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!thisUpdate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!nextUpdate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!singleExtensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void PKIStatusInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	status.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	statusString.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	failInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool PKIStatusInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!status.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!statusString.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!failInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void ContentInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	contentType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	content.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool ContentInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!contentType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!content.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CrlIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	crlissuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	crlIssuedTime.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	crlNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CrlIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!crlissuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!crlIssuedTime.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!crlNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CrlValidatedID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	crlHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	crlIdentifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CrlValidatedID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!crlHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!crlIdentifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void MessageImprint::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	hashAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	hashedMessage.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool MessageImprint::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!hashAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!hashedMessage.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void UserNotice::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	noticeRef.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	explicitText.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool UserNotice::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!noticeRef.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!explicitText.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void NoticeReference::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	organization.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(noticeNumbers, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool NoticeReference::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!organization.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn, cbIn, cbUsed, noticeNumbers))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OcspIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	ocspResponderID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	producedAt.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OcspIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!ocspResponderID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!producedAt.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CrlOcspRef::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	EncodeSet(crlids, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	ocspids.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRev.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CrlOcspRef::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, crlids))
		return false;

	offset += cbUsed;
	if (!ocspids.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherRev.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherRevRefs::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	otherRevRefType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRevRefs.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OtherRevRefs::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!otherRevRefType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherRevRefs.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OcspListID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	EncodeSet(ocspResponses, pOut, cbOut, cbUsed);
}

void RevocationValues::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	EncodeSet(crlVals, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(ocspVals, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRevVals.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool RevocationValues::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, crlVals))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, ocspVals))
		return false;

	offset += cbUsed;
	if (!otherRevVals.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherRevVals::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	otherRevValType.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRevVals.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OtherRevVals::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!otherRevValType.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherRevVals.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void BasicOCSPResponse::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	tbsResponseData.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signature.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(certs, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool BasicOCSPResponse::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!tbsResponseData.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signature.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, certs))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void ResponseData::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	responderID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	producedAt.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(responses, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	extensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool ResponseData::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!responderID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!producedAt.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, responses))
		return false;

	offset += cbUsed;
	if (!extensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SigningCertificateV2::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	EncodeSet(certs, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(policies, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SigningCertificateV2::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, certs))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, policies))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SubjectPublicKeyInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	algorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	subjectPublicKey.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SubjectPublicKeyInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!algorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!subjectPublicKey.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = cbUsed + offset;
	return true;
}

void Certificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	tbsCertificate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureValue.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool Certificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!tbsCertificate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureValue.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void TBSCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serialNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signature.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	validity.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	subject.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	subjectPublicKeyInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerUniqueID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	subjectUniqueID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	extensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool TBSCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	// Note - the way that app-specific types seem to work are that
	// they are optional, but we're treating this one as required.
	// A V3 cert will always have this, to support a V2 cert, need to find a way to generate them
	// for testing.
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!serialNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signature.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!validity.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!subject.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!subjectPublicKeyInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	// The following may not be present, and may need to be skipped
	if (*(pIn + offset) == 0xA1)
	{
		if (!issuerUniqueID.Decode(pIn + offset, cbIn - offset, cbUsed))
			return false;

		offset += cbUsed;
	}

	if (*(pIn + offset) == 0xA2)
	{
		if (!subjectUniqueID.Decode(pIn + offset, cbIn - offset, cbUsed))
			return false;

		offset += cbUsed;
	}

	if (*(pIn + offset) == 0xA3)
	{
		if (!extensions.Decode(pIn + offset, cbIn - offset, cbUsed))
			return false;

		offset += cbUsed;
	}

	cbUsed = offset;
	return true;
}

void CertificateList::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	tbsCertList.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureValue.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CertificateList::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!tbsCertList.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signatureValue.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void TBSCertList::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signature.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	thisUpdate.Encode(pOut + offset, cbNeeded - offset, cbUsed);	
	offset += cbUsed;

	nextUpdate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	revokedCertificates.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;
	
	crlExtensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool TBSCertList::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signature.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!thisUpdate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!nextUpdate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!revokedCertificates.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!crlExtensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void PolicyInformation::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	policyIdentifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(policyQualifiers, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool PolicyInformation::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!policyIdentifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, policyQualifiers))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void ESSCertID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	certHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerSerial.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool ESSCertID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!certHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerSerial.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SigningCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	EncodeSet(certs, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(policies, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SigningCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, certs))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, policies))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void ESSCertIDv2::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	hashAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	certHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerSerial.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool ESSCertIDv2::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!hashAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!certHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerSerial.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void PolicyQualifierInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	policyQualifierId.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	qualifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool PolicyQualifierInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!policyQualifierId.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!qualifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void IssuerAndSerialNumber::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	issuer.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serialNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool IssuerAndSerialNumber::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!issuer.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;

	if (!serialNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = cbUsed + offset;
	return true;
}

void Extension::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	extnID.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	if(critical.GetValue())
	{
		critical.Encode(pOut + offset, cbNeeded - offset, cbUsed);
		offset += cbUsed;
	}

	extnValue.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = offset + cbUsed;
}

bool Extension::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!extnID.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	// This might not be present
	if (!critical.Decode(pIn + offset, cbIn - offset, cbUsed))
	{
		// Ought to be false by default, but this is more readable
		critical.SetValue(false);
	}

	offset += cbUsed;
	if (!extnValue.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = cbUsed + offset;
	return true;
}

void CertStatus::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	revoked.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CertStatus::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!revoked.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

bool DisplayText::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	if (cbIn < 2)
		return false;

	switch (static_cast<DerType>(pIn[0]))
	{
	case DerType::VisibleString:
		type = DisplayTextType::Visible;
		break;
	case DerType::UTF8String:
		type = DisplayTextType::UTF8;
		break;
	case DerType::BMPString:
		type = DisplayTextType::BMP;
		break;
	case DerType::Null:
		type = DisplayTextType::NotSet;
		break;
	default:
		return false;
	}

	return value.Decode(pIn, cbIn, cbUsed);
}

void SignerInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	sid.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	digestAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(signedAttrs, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signatureAlgorithm.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	signature.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(unsignedAttrs, pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool SignerInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!sid.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!digestAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, signedAttrs))
		return false;

	offset += cbUsed;
	if (!signatureAlgorithm.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!signature.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, unsignedAttrs))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherCertificateFormat::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherCertFormat.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherCert.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OtherCertificateFormat::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!otherCertFormat.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherCert.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void EDIPartyName::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	nameAssigner.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	partyName.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool EDIPartyName::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!nameAssigner.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!partyName.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void RevocationEntry::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	userCertificate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	revocationDate.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	crlEntryExtensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool RevocationEntry::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!userCertificate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!revocationDate.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!crlEntryExtensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherRevocationInfoFormat::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRevInfoFormat.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherRevInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OtherRevocationInfoFormat::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!otherRevInfoFormat.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!otherRevInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SignedData::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(digestAlgorithms, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	encapContentInfo.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(crls, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(signerInfos, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SignedData::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, digestAlgorithms))
		return false;

	offset += cbUsed;
	if (!encapContentInfo.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, certificates))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, crls))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, signerInfos))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SigPolicyQualifierInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	sigPolicyQualifierId.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	sigQualifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool SigPolicyQualifierInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!sigPolicyQualifierId.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!sigQualifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SignaturePolicyId::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	sigPolicyId.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	sigPolicyHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(sigPolicyQualifiers, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SignaturePolicyId::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!sigPolicyId.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!sigPolicyHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, sigPolicyQualifiers))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SPUserNotice::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	noticeRef.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	explicitText.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool SPUserNotice::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!noticeRef.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!explicitText.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CommitmentTypeQualifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	commitmentTypeIdentifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	qualifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool CommitmentTypeQualifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!commitmentTypeIdentifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!qualifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void CommitmentTypeIndication::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	commitmentTypeId.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(commitmentTypeQualifier, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool CommitmentTypeIndication::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!commitmentTypeId.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, commitmentTypeQualifier))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SignerLocation::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	countryName.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	localityName.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(postalAdddress, pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SignerLocation::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!countryName.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!localityName.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, postalAdddress))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void SignerAttribute::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	EncodeSet(claimedAttributes, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	certifiedAttributes.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool SignerAttribute::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!DecodeSet(pIn + offset, cbIn - offset, cbUsed, claimedAttributes))
		return false;

	offset += cbUsed;
	if (!certifiedAttributes.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void TimeStampReq::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	messageImprint.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	reqPolicy.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	nonce.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	certReq.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	extensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool TimeStampReq::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!messageImprint.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!reqPolicy.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!nonce.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!certReq.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!extensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void TimeStampResp::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	status.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	timeStampToken.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool TimeStampResp::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!status.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!timeStampToken.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void TSTInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	version.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	policy.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	messageImprint.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	serialNumber.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	genTime.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	accuracy.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	ordering.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	nonce.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	tsa.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	extensions.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool TSTInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!version.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!policy.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!messageImprint.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!serialNumber.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!genTime.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!accuracy.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!ordering.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!nonce.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!tsa.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!extensions.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OtherCertId::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	otherCertHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	issuerSerial.Encode(pOut + offset, cbNeeded - offset, cbUsed);

	cbUsed = cbNeeded;
}

bool OtherCertId::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!otherCertHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!issuerSerial.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void OcspResponsesID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	size_t offset = 0;

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	ocspIdentifier.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	ocspRepHash.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool OcspResponsesID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!ocspIdentifier.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!ocspRepHash.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void Validity::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	notBefore.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	notAfter.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool Validity::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!notBefore.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!notAfter.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}

void AttributeTypeAndValue::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
	size_t offset = 0;
	size_t cbNeeded = EncodedSize();

	if (cbNeeded > cbOut)
		throw std::overflow_error("Overflow in Encode");

	pOut[0] = static_cast<unsigned char>(DerType::ConstructedSequence);
	offset = 1;

	if (!EncodeSize(cbData, pOut + offset, cbNeeded - offset, cbUsed))
		throw std::exception("Error in EncodeSize");

	offset += cbUsed;

	type.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	offset += cbUsed;

	value.Encode(pOut + offset, cbNeeded - offset, cbUsed);
	cbUsed = cbNeeded;
}

bool AttributeTypeAndValue::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
	size_t offset = 0;
	bool isNull = false;

	if (!DecodeSequence(pIn, cbIn, cbUsed, isNull))
		return false;

	if (isNull)
		return true;

	offset += cbUsed;
	if (!type.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	offset += cbUsed;
	if (!value.Decode(pIn + offset, cbIn - offset, cbUsed))
		return false;

	cbUsed = offset + cbUsed;
	return true;
}
