// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"

const std::string hashOids[] =
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

void Accuracy::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    seconds.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    millis.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    micros.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Accuracy::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!seconds.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!millis.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!micros.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void AlgorithmIdentifier::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    algorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    parameters.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool AlgorithmIdentifier::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();

    if (sh.IsAllUsed())
        return true;

    if (!parameters.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void Attribute::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    attrType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, attrValues, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Attribute::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!attrType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (DecodeSet(sh.DataPtr(in), sh.CurrentSize(), attrValues))
    {
        return true;
    }

    return false;
}

void EncapsulatedContentInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    eContentType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    eContent.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool EncapsulatedContentInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!eContentType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!eContent.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void IssuerSerial::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    issuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serial.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerUID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool IssuerSerial::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!serial.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerUID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void ObjectDigestInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    digestedObjectType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherObjectTypeID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    digestAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    objectDigest.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool ObjectDigestInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!digestedObjectType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherObjectTypeID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!digestAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!objectDigest.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void Holder::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    baseCertificateID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    entityName.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    objectDigestInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Holder::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!baseCertificateID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!entityName.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!objectDigestInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OtherHashAlgAndValue::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    hashValue.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherHashAlgAndValue::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!hashValue.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void V2Form::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    issuerName.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    baseCertificateID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    objectDigestInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool V2Form::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuerName.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!baseCertificateID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!objectDigestInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void AttCertValidityPeriod::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    notBeforeTime.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    notAfterTime.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool AttCertValidityPeriod::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBeforeTime.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!notAfterTime.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void AttributeCertificateInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    holder.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signature.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serialNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    attrCertValidityPeriod.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, attributes, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerUniqueID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    extensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool AttributeCertificateInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!holder.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!holder.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signature.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!serialNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!attrCertValidityPeriod.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), attributes))
        return false;

    sh.Update();
    if (!issuerUniqueID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!extensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void AttributeCertificate::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    acinfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureValue.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool AttributeCertificate::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!acinfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureValue.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CertID::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerNameHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerKeyHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serialNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CertID::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerNameHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerKeyHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!serialNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void RevokedInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    revocationTime.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    revocationReason.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool RevokedInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revocationTime.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!revocationReason.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void SingleResponse::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    certID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    certStatus.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    thisUpdate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    nextUpdate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    singleExtensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SingleResponse::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!certStatus.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!thisUpdate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!nextUpdate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!singleExtensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void PKIStatusInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    status.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    statusString.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    failInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool PKIStatusInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!statusString.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!failInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void ContentInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    contentType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    content.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool ContentInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!contentType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!content.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CrlIdentifier::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    crlissuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    crlIssuedTime.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    crlNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CrlIdentifier::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlissuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!crlIssuedTime.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!crlNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CrlValidatedID::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    crlHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    crlIdentifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CrlValidatedID::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!crlIdentifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void MessageImprint::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    hashedMessage.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool MessageImprint::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!hashedMessage.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void UserNotice::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    noticeRef.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    explicitText.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool UserNotice::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!explicitText.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void NoticeReference::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    organization.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, noticeNumbers, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool NoticeReference::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!organization.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), noticeNumbers))
        return false;

    return true;
}

void OcspIdentifier::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    ocspResponderID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    producedAt.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OcspIdentifier::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspResponderID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!producedAt.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CrlOcspRef::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crlids, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    ocspids.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherRev.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CrlOcspRef::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), crlids))
        return false;

    sh.Update();
    if (!ocspids.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherRev.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OtherRevRefs::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    otherRevRefType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherRevRefs.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherRevRefs::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevRefType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherRevRefs.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OcspListID::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspResponses, out, cbUsed);
}

void RevocationValues::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crlVals, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspVals, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherRevVals.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool RevocationValues::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), crlVals))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), ocspVals))
        return false;

    sh.Update();
    if (!otherRevVals.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OtherRevVals::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    otherRevValType.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherRevVals.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherRevVals::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevValType.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherRevVals.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void BasicOCSPResponse::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    tbsResponseData.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signature.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool BasicOCSPResponse::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsResponseData.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signature.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), certs))
        return false;

    return true;
}

void ResponseData::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    responderID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    producedAt.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, responses, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    extensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool ResponseData::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!responderID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!producedAt.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), responses))
        return false;

    sh.Update();
    if (!extensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void SigningCertificateV2::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SigningCertificateV2::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), certs))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), policies))
        return false;

    return true;
}

void SubjectPublicKeyInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    algorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    subjectPublicKey.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SubjectPublicKeyInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!subjectPublicKey.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void Certificate::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    tbsCertificate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureValue.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Certificate::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertificate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureValue.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void TBSCertificate::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serialNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signature.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    validity.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    subject.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    subjectPublicKeyInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerUniqueID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    subjectUniqueID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    extensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool TBSCertificate::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    // A V3 cert should always have this, anything with extensions must be v3
    // If it is missing, it implies v1 (value of 0)
    if (sh.DataPtr(in)[0] == std::byte{0xA0})
    {
        if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
            return false;
    }

    sh.Update();
    if (!serialNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signature.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!validity.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!subject.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!subjectPublicKeyInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    // The following may not be present, and may need to be skipped
    if (sh.DataPtr(in)[0] == std::byte{0xA1})
    {
        if (!issuerUniqueID.Decode(sh.DataPtr(in), sh.CurrentSize()))
            return false;

        sh.Update();
    }

    if (sh.DataPtr(in)[0] == std::byte{0xA2})
    {
        if (!subjectUniqueID.Decode(sh.DataPtr(in), sh.CurrentSize()))
            return false;

        sh.Update();
    }

    if (sh.DataPtr(in)[0] == std::byte{0xA3})
    {
        if (!extensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
            return false;

        sh.Update();
    }

    return true;
}

void CertificateList::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    tbsCertList.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureValue.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CertificateList::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertList.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signatureValue.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void TBSCertList::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signature.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    thisUpdate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    nextUpdate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    revokedCertificates.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    crlExtensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool TBSCertList::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    // Version is optional
    if (sh.DataPtr(in)[0] == static_cast<std::byte>(DerType::Integer))
    {
        if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
            return false;

        sh.Update();
    }

    if (!signature.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!thisUpdate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();

    // This is also optional, and may not be present
    if (nextUpdate.Decode(sh.DataPtr(in), sh.CurrentSize()))
    {
        sh.Update();
    }

    // These are optional, and may not be present
    if (revokedCertificates.Decode(sh.DataPtr(in), sh.CurrentSize()))
        sh.Update();

    if (sh.IsAllUsed()) // extensions are optional
        return true;

    if (!crlExtensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void PolicyInformation::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    policyIdentifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policyQualifiers, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool PolicyInformation::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyIdentifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (sh.IsAllUsed()) // policy qualifiers are optional
        return true;

    size_t cbSize = 0;
    size_t cbPrefix = 0;
    bool ret = DecodeSequenceOf(sh.DataPtr(in), cbPrefix, cbSize, policyQualifiers);

    if (ret)
    {
        cbData = cbSize;
        sh.CurrentSize() = cbSize + cbPrefix;
    }

    return ret;
}

void ESSCertID::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    certHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerSerial.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool ESSCertID::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerSerial.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void SigningCertificate::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SigningCertificate::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), certs))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), policies))
        return false;

    return true;
}

void ESSCertIDv2::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    hashAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    certHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerSerial.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool ESSCertIDv2::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!certHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerSerial.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void PolicyQualifierInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    policyQualifierId.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    qualifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool PolicyQualifierInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyQualifierId.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!qualifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void IssuerAndSerialNumber::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    issuer.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serialNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool IssuerAndSerialNumber::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();

    if (!serialNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void Extension::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    extnID.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    if (critical.GetValue())
    {
        critical.Encode(eh.DataPtr(out), eh.CurrentSize());
        eh.Update();
    }

    extnValue.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Extension::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!extnID.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    // This might not be present
    if (!critical.Decode(sh.DataPtr(in), sh.CurrentSize()))
    {
        // Ought to be false by default, but this is more readable
        critical.SetValue(false);
    }

    sh.Update();
    if (!extnValue.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CertStatus::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    revoked.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CertStatus::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revoked.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

bool DisplayText::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    if (in.size() < 2)
        return false;

// Disable unused enum values warning, it adds a lot of noise here and only specific types are supported
#pragma warning(disable : 4061)
    switch (static_cast<DerType>(in[0]))
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
#pragma warning(default : 4061)

    return value.Decode(in, cbUsed);
}

void SignerInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    sid.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    digestAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, signedAttrs, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signatureAlgorithm.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    signature.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, unsignedAttrs, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SignerInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!sid.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!digestAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), signedAttrs))
        return false;

    sh.Update();
    if (!signatureAlgorithm.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!signature.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), unsignedAttrs))
        return false;

    return true;
}

void OtherCertificateFormat::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    otherCertFormat.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherCert.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherCertificateFormat::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertFormat.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherCert.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void EDIPartyName::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    nameAssigner.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    partyName.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool EDIPartyName::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!nameAssigner.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!partyName.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void RevocationEntry::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    userCertificate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    revocationDate.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    crlEntryExtensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool RevocationEntry::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    // We have an optional sequence of RevocationEntry object
    // and won't know if there really is a RevocationEntry until
    // we get here
    if (sh.DataPtr(in)[0] != static_cast<std::byte>(DerType::Integer))
    {
        cbUsed = 0;
        sh.Reset(); // This keeps us from throwing
        return false;
    }

    if (!userCertificate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!revocationDate.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();

    if (sh.IsAllUsed()) // crlEntryExtensions are optional
        return true;

    if (!crlEntryExtensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OtherRevocationInfoFormat::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    otherRevInfoFormat.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    otherRevInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherRevocationInfoFormat::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevInfoFormat.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!otherRevInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void SignedData::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, digestAlgorithms, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    encapContentInfo.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, crls, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, signerInfos, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SignedData::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), digestAlgorithms))
        return false;

    sh.Update();
    if (!encapContentInfo.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), certificates))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), crls))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), signerInfos))
        return false;

    return true;
}

void SigPolicyQualifierInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    sigPolicyQualifierId.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    sigQualifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SigPolicyQualifierInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyQualifierId.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!sigQualifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void SignaturePolicyId::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    sigPolicyId.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    sigPolicyHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, sigPolicyQualifiers, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SignaturePolicyId::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyId.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!sigPolicyHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), sigPolicyQualifiers))
        return false;

    return true;
}

void SPUserNotice::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    noticeRef.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    explicitText.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SPUserNotice::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!explicitText.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CommitmentTypeQualifier::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    commitmentTypeIdentifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    qualifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CommitmentTypeQualifier::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeIdentifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!qualifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void CommitmentTypeIndication::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    commitmentTypeId.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, commitmentTypeQualifier, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool CommitmentTypeIndication::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeId.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), commitmentTypeQualifier))
        return false;

    return true;
}

void SignerLocation::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    countryName.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    localityName.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    EncodeSetOrSequenceOf(DerType::ConstructedSet, postalAdddress, eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SignerLocation::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!countryName.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!localityName.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), postalAdddress))
        return false;

    return true;
}

void SignerAttribute::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    EncodeSetOrSequenceOf(DerType::ConstructedSet, claimedAttributes, eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    certifiedAttributes.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool SignerAttribute::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!DecodeSet(sh.DataPtr(in), sh.CurrentSize(), claimedAttributes))
        return false;

    sh.Update();
    if (!certifiedAttributes.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void TimeStampReq::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    messageImprint.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    reqPolicy.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    nonce.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    certReq.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    extensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool TimeStampReq::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!messageImprint.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!reqPolicy.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!nonce.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!certReq.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!extensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void TimeStampResp::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    status.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    timeStampToken.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool TimeStampResp::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!timeStampToken.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void TSTInfo::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    version.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    policy.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    messageImprint.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    serialNumber.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    genTime.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    accuracy.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    ordering.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    nonce.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    tsa.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    extensions.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool TSTInfo::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!policy.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!messageImprint.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!serialNumber.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!genTime.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!accuracy.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!ordering.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!nonce.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!tsa.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!extensions.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OtherCertId::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    otherCertHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    issuerSerial.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OtherCertId::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!issuerSerial.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void OcspResponsesID::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    ocspIdentifier.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    ocspRepHash.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool OcspResponsesID::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspIdentifier.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!ocspRepHash.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void Validity::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    notBefore.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    notAfter.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool Validity::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBefore.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!notAfter.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}

void AttributeTypeAndValue::Encode(std::span<std::byte> out, size_t &cbUsed)
{
    EncodeHelper eh(cbUsed);

    eh.Init(EncodedSize(), out, static_cast<std::byte>(DerType::ConstructedSequence), cbData);

    type.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Update();

    value.Encode(eh.DataPtr(out), eh.CurrentSize());
    eh.Finalize();
}

bool AttributeTypeAndValue::Decode(std::span<const std::byte> in, size_t &cbUsed)
{
    SequenceHelper sh(cbUsed);

    switch (sh.Init(in, this->cbData))
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!type.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    sh.Update();
    if (!value.Decode(sh.DataPtr(in), sh.CurrentSize()))
        return false;

    return true;
}
