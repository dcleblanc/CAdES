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
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

	seconds.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	millis.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	micros.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Accuracy::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!seconds.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!millis.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!micros.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void AlgorithmIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    algorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	parameters.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool AlgorithmIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!algorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!parameters.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void Attribute::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    attrType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	EncodeSetOrSequenceOf(DerType::ConstructedSet, attrValues, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Attribute::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!attrType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), attrValues))
	{
		return true;
	}

	return false;
}

void EncapsulatedContentInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    eContentType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	eContent.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool EncapsulatedContentInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!eContentType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!eContent.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void IssuerSerial::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    issuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serial.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerUID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool IssuerSerial::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!issuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!serial.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerUID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void ObjectDigestInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    digestedObjectType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherObjectTypeID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	digestAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	objectDigest.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool ObjectDigestInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!digestedObjectType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherObjectTypeID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!digestAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!objectDigest.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void Holder::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    baseCertificateID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	entityName.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	objectDigestInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Holder::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!baseCertificateID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!entityName.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!objectDigestInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OtherHashAlgAndValue::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

	hashAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	hashValue.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherHashAlgAndValue::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!hashValue.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void V2Form::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    issuerName.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	baseCertificateID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	objectDigestInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool V2Form::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!issuerName.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!baseCertificateID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!objectDigestInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void AttCertValidityPeriod::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    notBeforeTime.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	notAfterTime.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool AttCertValidityPeriod::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!notBeforeTime.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!notAfterTime.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void AttributeCertificateInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	holder.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signature.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serialNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	attrCertValidityPeriod.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, attributes, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerUniqueID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	extensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool AttributeCertificateInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }
    
    if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!holder.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!holder.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signature.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!serialNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!attrCertValidityPeriod.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), attributes))
		return false;

    sh.Update();
	if (!issuerUniqueID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!extensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void AttributeCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

	acinfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureValue.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool AttributeCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!acinfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureValue.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CertID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerNameHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerKeyHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serialNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CertID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!hashAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerNameHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerKeyHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!serialNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void RevokedInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    revocationTime.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	revocationReason.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool RevokedInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!revocationTime.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	sh.Update();
	if (!revocationReason.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void SingleResponse::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    certID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	certStatus.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	thisUpdate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	nextUpdate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	singleExtensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SingleResponse::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!certID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!certStatus.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!thisUpdate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!nextUpdate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!singleExtensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void PKIStatusInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

	status.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	statusString.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	failInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool PKIStatusInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!status.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!statusString.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!failInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void ContentInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    contentType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	content.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool ContentInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!contentType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!content.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CrlIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    crlissuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	crlIssuedTime.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	crlNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CrlIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!crlissuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!crlIssuedTime.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!crlNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CrlValidatedID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    crlHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	crlIdentifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CrlValidatedID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!crlHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!crlIdentifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void MessageImprint::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	hashedMessage.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool MessageImprint::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!hashAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!hashedMessage.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void UserNotice::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);
    
    noticeRef.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	explicitText.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool UserNotice::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!noticeRef.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!explicitText.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void NoticeReference::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    organization.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, noticeNumbers, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool NoticeReference::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!organization.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), noticeNumbers))
		return false;

	return true;
}

void OcspIdentifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    ocspResponderID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	producedAt.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OcspIdentifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspResponderID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!producedAt.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CrlOcspRef::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crlids, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	ocspids.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherRev.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CrlOcspRef::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), crlids))
		return false;

    sh.Update();
	if (!ocspids.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherRev.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OtherRevRefs::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    otherRevRefType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherRevRefs.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherRevRefs::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevRefType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherRevRefs.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OcspListID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspResponses, pOut, cbOut, cbUsed);
}

void RevocationValues::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crlVals, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspVals, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherRevVals.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool RevocationValues::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), crlVals))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), ocspVals))
		return false;

    sh.Update();
	if (!otherRevVals.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OtherRevVals::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    otherRevValType.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherRevVals.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherRevVals::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }
    
    if (!otherRevValType.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherRevVals.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void BasicOCSPResponse::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    tbsResponseData.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signature.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool BasicOCSPResponse::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!tbsResponseData.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signature.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), certs))
		return false;

	return true;
}

void ResponseData::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	responderID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	producedAt.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, responses, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	extensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool ResponseData::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!responderID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!producedAt.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), responses))
		return false;

    sh.Update();
	if (!extensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void SigningCertificateV2::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SigningCertificateV2::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), certs))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), policies))
		return false;

	return true;
}

void SubjectPublicKeyInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    algorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	subjectPublicKey.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SubjectPublicKeyInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!algorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!subjectPublicKey.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void Certificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    tbsCertificate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureValue.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Certificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!tbsCertificate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureValue.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void TBSCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);
    
    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serialNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signature.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	validity.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	subject.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	subjectPublicKeyInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerUniqueID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	subjectUniqueID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	extensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool TBSCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    // A V3 cert should always have this, anything with extensions must be v3
    // If it is missing, it implies v1 (value of 0)
    if (*(sh.DataPtr(pIn)) == 0xA0)
    {
        if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
            return false;
    }

    sh.Update();
	if (!serialNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signature.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!validity.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!subject.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!subjectPublicKeyInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	// The following may not be present, and may need to be skipped
	if (*(sh.DataPtr(pIn)) == 0xA1)
	{
		if (!issuerUniqueID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
			return false;

        sh.Update();
	}

	if (*(sh.DataPtr(pIn)) == 0xA2)
	{
		if (!subjectUniqueID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
			return false;

        sh.Update();
	}

	if (*(sh.DataPtr(pIn)) == 0xA3)
	{
		if (!extensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
			return false;

        sh.Update();
	}

	return true;
}

void CertificateList::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    tbsCertList.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureValue.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CertificateList::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!tbsCertList.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signatureValue.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void TBSCertList::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signature.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	thisUpdate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	nextUpdate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	revokedCertificates.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();
	
	crlExtensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool TBSCertList::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signature.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!thisUpdate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!nextUpdate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!revokedCertificates.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!crlExtensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void PolicyInformation::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    policyIdentifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policyQualifiers, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool PolicyInformation::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!policyIdentifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
    if (sh.IsAllUsed()) // policy qualifiers are optional
        return true;

	if (!DecodeSequenceOf(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), policyQualifiers))
		return false;

	return true;
}

void ESSCertID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    certHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerSerial.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool ESSCertID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!certHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerSerial.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void SigningCertificate::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SigningCertificate::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), certs))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), policies))
		return false;

	return true;
}

void ESSCertIDv2::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	certHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerSerial.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool ESSCertIDv2::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!certHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerSerial.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void PolicyQualifierInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    policyQualifierId.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	qualifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool PolicyQualifierInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyQualifierId.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!qualifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void IssuerAndSerialNumber::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    issuer.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serialNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool IssuerAndSerialNumber::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();

	if (!serialNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void Extension::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    extnID.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	if(critical.GetValue())
	{
		critical.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
        eh.Update();
	}

	extnValue.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Extension::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!extnID.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	// This might not be present
	if (!critical.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
	{
		// Ought to be false by default, but this is more readable
		critical.SetValue(false);
	}

    sh.Update();
	if (!extnValue.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CertStatus::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    revoked.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CertStatus::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!revoked.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

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
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	sid.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	digestAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, signedAttrs, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signatureAlgorithm.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	signature.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, unsignedAttrs, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SignerInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!sid.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!digestAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), signedAttrs))
		return false;

    sh.Update();
	if (!signatureAlgorithm.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!signature.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), unsignedAttrs))
		return false;

	return true;
}

void OtherCertificateFormat::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    otherCertFormat.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherCert.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherCertificateFormat::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertFormat.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherCert.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void EDIPartyName::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    nameAssigner.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	partyName.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool EDIPartyName::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!nameAssigner.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!partyName.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void RevocationEntry::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    userCertificate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	revocationDate.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	crlEntryExtensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool RevocationEntry::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!userCertificate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!revocationDate.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!crlEntryExtensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OtherRevocationInfoFormat::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);
    
    otherRevInfoFormat.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	otherRevInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherRevocationInfoFormat::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!otherRevInfoFormat.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!otherRevInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void SignedData::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, digestAlgorithms, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	encapContentInfo.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crls, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, signerInfos, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SignedData::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), digestAlgorithms))
		return false;

    sh.Update();
	if (!encapContentInfo.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), certificates))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), crls))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), signerInfos))
		return false;

	return true;
}

void SigPolicyQualifierInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    sigPolicyQualifierId.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	sigQualifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SigPolicyQualifierInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!sigPolicyQualifierId.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!sigQualifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void SignaturePolicyId::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    sigPolicyId.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	sigPolicyHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, sigPolicyQualifiers, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SignaturePolicyId::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyId.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!sigPolicyHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), sigPolicyQualifiers))
		return false;

	return true;
}

void SPUserNotice::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    noticeRef.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	explicitText.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SPUserNotice::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!explicitText.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CommitmentTypeQualifier::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    commitmentTypeIdentifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	qualifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CommitmentTypeQualifier::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeIdentifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!qualifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void CommitmentTypeIndication::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    commitmentTypeId.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, commitmentTypeQualifier, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool CommitmentTypeIndication::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!commitmentTypeId.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), commitmentTypeQualifier))
		return false;

	return true;
}

void SignerLocation::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    countryName.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	localityName.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, postalAdddress, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SignerLocation::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }
    
    if (!countryName.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!localityName.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), postalAdddress))
		return false;

	return true;
}

void SignerAttribute::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, claimedAttributes, eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	certifiedAttributes.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool SignerAttribute::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize(), claimedAttributes))
		return false;

    sh.Update();
	if (!certifiedAttributes.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void TimeStampReq::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	messageImprint.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	reqPolicy.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	nonce.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	certReq.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	extensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool TimeStampReq::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!messageImprint.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!reqPolicy.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!nonce.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!certReq.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!extensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void TimeStampResp::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    status.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	timeStampToken.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool TimeStampResp::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!timeStampToken.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void TSTInfo::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	policy.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	messageImprint.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	serialNumber.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	genTime.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	accuracy.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	ordering.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	nonce.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	tsa.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	extensions.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool TSTInfo::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }
    
    if (!version.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!policy.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!messageImprint.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!serialNumber.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!genTime.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!accuracy.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!ordering.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!nonce.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!tsa.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!extensions.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OtherCertId::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    otherCertHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	issuerSerial.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OtherCertId::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!otherCertHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!issuerSerial.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void OcspResponsesID::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    ocspIdentifier.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	ocspRepHash.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool OcspResponsesID::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!ocspIdentifier.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!ocspRepHash.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void Validity::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    notBefore.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	notAfter.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool Validity::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

	if (!notBefore.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!notAfter.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}

void AttributeTypeAndValue::Encode(unsigned char * pOut, size_t cbOut, size_t & cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), pOut, cbOut, static_cast<unsigned char>(DerType::ConstructedSequence), cbData);

    type.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
    eh.Update();

	value.Encode(eh.DataPtr(pOut), eh.DataSize(), eh.CurrentSize());
	eh.Finalize();
}

bool AttributeTypeAndValue::Decode(const unsigned char * pIn, size_t cbIn, size_t & cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(pIn, cbIn, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!type.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

    sh.Update();
	if (!value.Decode(sh.DataPtr(pIn), sh.DataSize(), sh.CurrentSize()))
		return false;

	return true;
}
