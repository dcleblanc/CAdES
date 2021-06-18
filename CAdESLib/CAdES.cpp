// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "CAdES.h"

#include "Common.h"
#include "DerTypes.h"
#include "Oids.h"

const std::string hashOids[] =
    {
        id_md2,
        id_md5,
        id_sha1,
        id_sha224,
        id_sha256,
        id_sha384,
        id_sha512};

AlgorithmIdentifier::AlgorithmIdentifier(HashAlgorithm alg) : algorithm(hashOids[static_cast<ptrdiff_t>(alg)])
{
    parameters.SetNull();
}

void Accuracy::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    seconds.Encode(eh.DataPtr(out));
    millis.Encode(eh.DataPtr(out));
    micros.Encode(eh.DataPtr(out));
}

bool Accuracy::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!seconds.Decode(innerDecoder))
        return false;

    if (!millis.Decode(innerDecoder))
        return false;

    if (!micros.Decode(innerDecoder))
        return false;

    return true;
}

void AlgorithmIdentifier::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    algorithm.Encode(eh.DataPtr(out));

    parameters.Encode(eh.DataPtr(out));
}

bool AlgorithmIdentifier::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(innerDecoder))
        return false;

    if (innerDecoder.Empty())
        return true;

    if (!parameters.Decode(innerDecoder))
        return false;

    return true;
}

void Attribute::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    attrType.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, attrValues, eh.DataPtr(out));
}

bool Attribute::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!attrType.Decode(innerDecoder))
        return false;

    if (decoder.DecodeSet(attrValues))
    {
        return true;
    }

    return false;
}

void EncapsulatedContentInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    eContentType.Encode(eh.DataPtr(out));

    eContent.Encode(eh.DataPtr(out));
}

bool EncapsulatedContentInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!eContentType.Decode(innerDecoder))
        return false;

    if (!eContent.Decode(innerDecoder))
        return false;

    return true;
}

void IssuerSerial::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    issuer.Encode(eh.DataPtr(out));

    serial.Encode(eh.DataPtr(out));

    issuerUID.Encode(eh.DataPtr(out));
}

bool IssuerSerial::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(innerDecoder))
        return false;

    if (!serial.Decode(innerDecoder))
        return false;

    if (!issuerUID.Decode(innerDecoder))
        return false;

    return true;
}

void ObjectDigestInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    digestedObjectType.Encode(eh.DataPtr(out));

    otherObjectTypeID.Encode(eh.DataPtr(out));

    digestAlgorithm.Encode(eh.DataPtr(out));

    objectDigest.Encode(eh.DataPtr(out));
}

bool ObjectDigestInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!digestedObjectType.Decode(innerDecoder))
        return false;

    if (!otherObjectTypeID.Decode(innerDecoder))
        return false;

    if (!digestAlgorithm.Decode(innerDecoder))
        return false;

    if (!objectDigest.Decode(innerDecoder))
        return false;

    return true;
}

void Holder::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    baseCertificateID.Encode(eh.DataPtr(out));

    entityName.Encode(eh.DataPtr(out));

    objectDigestInfo.Encode(eh.DataPtr(out));
}

bool Holder::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!baseCertificateID.Decode(innerDecoder))
        return false;

    if (!entityName.Decode(innerDecoder))
        return false;

    if (!objectDigestInfo.Decode(innerDecoder))
        return false;

    return true;
}

void OtherHashAlgAndValue::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    hashAlgorithm.Encode(eh.DataPtr(out));

    hashValue.Encode(eh.DataPtr(out));
}

bool OtherHashAlgAndValue::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(innerDecoder))
        return false;

    if (!hashValue.Decode(innerDecoder))
        return false;

    return true;
}

void V2Form::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    issuerName.Encode(eh.DataPtr(out));

    baseCertificateID.Encode(eh.DataPtr(out));

    objectDigestInfo.Encode(eh.DataPtr(out));
}

bool V2Form::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuerName.Decode(innerDecoder))
        return false;

    if (!baseCertificateID.Decode(innerDecoder))
        return false;

    if (!objectDigestInfo.Decode(innerDecoder))
        return false;

    return true;
}

void AttCertValidityPeriod::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    notBeforeTime.Encode(eh.DataPtr(out));

    notAfterTime.Encode(eh.DataPtr(out));
}

bool AttCertValidityPeriod::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBeforeTime.Decode(innerDecoder))
        return false;

    if (!notAfterTime.Decode(innerDecoder))
        return false;

    return true;
}

void AttributeCertificateInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    holder.Encode(eh.DataPtr(out));

    issuer.Encode(eh.DataPtr(out));

    signature.Encode(eh.DataPtr(out));

    serialNumber.Encode(eh.DataPtr(out));

    attrCertValidityPeriod.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, attributes, eh.DataPtr(out));

    issuerUniqueID.Encode(eh.DataPtr(out));

    extensions.Encode(eh.DataPtr(out));
}

bool AttributeCertificateInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!holder.Decode(innerDecoder))
        return false;

    if (!issuer.Decode(innerDecoder))
        return false;

    if (!holder.Decode(innerDecoder))
        return false;

    if (!signature.Decode(innerDecoder))
        return false;

    if (!serialNumber.Decode(innerDecoder))
        return false;

    if (!attrCertValidityPeriod.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(attributes))
        return false;

    if (!issuerUniqueID.Decode(innerDecoder))
        return false;

    if (!extensions.Decode(innerDecoder))
        return false;

    return true;
}

void AttributeCertificate::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    acinfo.Encode(eh.DataPtr(out));

    signatureAlgorithm.Encode(eh.DataPtr(out));

    signatureValue.Encode(eh.DataPtr(out));
}

bool AttributeCertificate::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!acinfo.Decode(innerDecoder))
        return false;

    if (!signatureAlgorithm.Decode(innerDecoder))
        return false;

    if (!signatureValue.Decode(innerDecoder))
        return false;

    return true;
}

void CertID::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    hashAlgorithm.Encode(eh.DataPtr(out));

    issuerNameHash.Encode(eh.DataPtr(out));

    issuerKeyHash.Encode(eh.DataPtr(out));

    serialNumber.Encode(eh.DataPtr(out));
}

bool CertID::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(innerDecoder))
        return false;

    if (!issuerNameHash.Decode(innerDecoder))
        return false;

    if (!issuerKeyHash.Decode(innerDecoder))
        return false;

    if (!serialNumber.Decode(innerDecoder))
        return false;

    return true;
}

void RevokedInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    revocationTime.Encode(eh.DataPtr(out));

    revocationReason.Encode(eh.DataPtr(out));
}

bool RevokedInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revocationTime.Decode(innerDecoder))
        return false;

    if (!revocationReason.Decode(innerDecoder))
        return false;

    return true;
}

void SingleResponse::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    certID.Encode(eh.DataPtr(out));

    certStatus.Encode(eh.DataPtr(out));

    thisUpdate.Encode(eh.DataPtr(out));

    nextUpdate.Encode(eh.DataPtr(out));

    singleExtensions.Encode(eh.DataPtr(out));
}

bool SingleResponse::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certID.Decode(innerDecoder))
        return false;

    if (!certStatus.Decode(innerDecoder))
        return false;

    if (!thisUpdate.Decode(innerDecoder))
        return false;

    if (!nextUpdate.Decode(innerDecoder))
        return false;

    if (!singleExtensions.Decode(innerDecoder))
        return false;

    return true;
}

void PKIStatusInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    status.Encode(eh.DataPtr(out));

    statusString.Encode(eh.DataPtr(out));

    failInfo.Encode(eh.DataPtr(out));
}

bool PKIStatusInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(innerDecoder))
        return false;

    if (!statusString.Decode(innerDecoder))
        return false;

    if (!failInfo.Decode(innerDecoder))
        return false;

    return true;
}

void ContentInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    contentType.Encode(eh.DataPtr(out));

    content.Encode(eh.DataPtr(out));
}

bool ContentInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!contentType.Decode(innerDecoder))
        return false;

    if (!content.Decode(innerDecoder))
        return false;

    return true;
}

void CrlIdentifier::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    crlissuer.Encode(eh.DataPtr(out));

    crlIssuedTime.Encode(eh.DataPtr(out));

    crlNumber.Encode(eh.DataPtr(out));
}

bool CrlIdentifier::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlissuer.Decode(innerDecoder))
        return false;

    if (!crlIssuedTime.Decode(innerDecoder))
        return false;

    if (!crlNumber.Decode(innerDecoder))
        return false;

    return true;
}

void CrlValidatedID::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    crlHash.Encode(eh.DataPtr(out));

    crlIdentifier.Encode(eh.DataPtr(out));
}

bool CrlValidatedID::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlHash.Decode(innerDecoder))
        return false;

    if (!crlIdentifier.Decode(innerDecoder))
        return false;

    return true;
}

void MessageImprint::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    hashAlgorithm.Encode(eh.DataPtr(out));

    hashedMessage.Encode(eh.DataPtr(out));
}

bool MessageImprint::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(innerDecoder))
        return false;

    if (!hashedMessage.Decode(innerDecoder))
        return false;

    return true;
}

void UserNotice::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    noticeRef.Encode(eh.DataPtr(out));

    explicitText.Encode(eh.DataPtr(out));
}

bool UserNotice::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(innerDecoder))
        return false;

    if (!explicitText.Decode(innerDecoder))
        return false;

    return true;
}

void NoticeReference::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    organization.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, noticeNumbers, eh.DataPtr(out));
}

bool NoticeReference::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!organization.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(noticeNumbers))
        return false;

    return true;
}

void OcspIdentifier::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    ocspResponderID.Encode(eh.DataPtr(out));

    producedAt.Encode(eh.DataPtr(out));
}

bool OcspIdentifier::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspResponderID.Decode(innerDecoder))
        return false;

    if (!producedAt.Decode(innerDecoder))
        return false;

    return true;
}

void CrlOcspRef::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, crlids, eh.DataPtr(out));

    ocspids.Encode(eh.DataPtr(out));

    otherRev.Encode(eh.DataPtr(out));
}

bool CrlOcspRef::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!decoder.DecodeSet(crlids))
        return false;

    if (!ocspids.Decode(innerDecoder))
        return false;

    if (!otherRev.Decode(innerDecoder))
        return false;

    return true;
}

void OtherRevRefs::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    otherRevRefType.Encode(eh.DataPtr(out));

    otherRevRefs.Encode(eh.DataPtr(out));
}

bool OtherRevRefs::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevRefType.Decode(innerDecoder))
        return false;

    if (!otherRevRefs.Decode(innerDecoder))
        return false;

    return true;
}

void OcspListID::Encode(std::span<std::byte> out)
{
    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspResponses, out);
}

void RevocationValues::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, crlVals, eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, ocspVals, eh.DataPtr(out));

    otherRevVals.Encode(eh.DataPtr(out));
}

bool RevocationValues::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!decoder.DecodeSet(crlVals))
        return false;

    if (!decoder.DecodeSet(ocspVals))
        return false;

    if (!otherRevVals.Decode(innerDecoder))
        return false;

    return true;
}

void OtherRevVals::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    otherRevValType.Encode(eh.DataPtr(out));

    otherRevVals.Encode(eh.DataPtr(out));
}

bool OtherRevVals::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevValType.Decode(innerDecoder))
        return false;

    if (!otherRevVals.Decode(innerDecoder))
        return false;

    return true;
}

void BasicOCSPResponse::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    tbsResponseData.Encode(eh.DataPtr(out));

    signatureAlgorithm.Encode(eh.DataPtr(out));

    signature.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out));
}

bool BasicOCSPResponse::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsResponseData.Decode(innerDecoder))
        return false;

    if (!signatureAlgorithm.Decode(innerDecoder))
        return false;

    if (!signature.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(certs))
        return false;

    return true;
}

void ResponseData::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    responderID.Encode(eh.DataPtr(out));

    producedAt.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, responses, eh.DataPtr(out));

    extensions.Encode(eh.DataPtr(out));
}

bool ResponseData::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!responderID.Decode(innerDecoder))
        return false;

    if (!producedAt.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(responses))
        return false;

    if (!extensions.Decode(innerDecoder))
        return false;

    return true;
}

void SigningCertificateV2::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(out));
}

bool SigningCertificateV2::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!decoder.DecodeSet(certs))
        return false;

    if (!decoder.DecodeSet(policies))
        return false;

    return true;
}

void SubjectPublicKeyInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    algorithm.Encode(eh.DataPtr(out));

    subjectPublicKey.Encode(eh.DataPtr(out));
}

bool SubjectPublicKeyInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(innerDecoder))
        return false;

    if (!subjectPublicKey.Decode(innerDecoder))
        return false;

    return true;
}

void Certificate::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    tbsCertificate.Encode(eh.DataPtr(out));

    signatureAlgorithm.Encode(eh.DataPtr(out));

    signatureValue.Encode(eh.DataPtr(out));
}

bool Certificate::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertificate.Decode(innerDecoder))
        return false;

    if (!signatureAlgorithm.Decode(innerDecoder))
        return false;

    if (!signatureValue.Decode(innerDecoder))
        return false;

    return true;
}

void TBSCertificate::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    serialNumber.Encode(eh.DataPtr(out));

    signature.Encode(eh.DataPtr(out));

    issuer.Encode(eh.DataPtr(out));

    validity.Encode(eh.DataPtr(out));

    subject.Encode(eh.DataPtr(out));

    subjectPublicKeyInfo.Encode(eh.DataPtr(out));

    issuerUniqueID.Encode(eh.DataPtr(out));

    subjectUniqueID.Encode(eh.DataPtr(out));

    extensions.Encode(eh.DataPtr(out));
}

bool TBSCertificate::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
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
    if (innerDecoder.RemainingData()[0] == std::byte{0xA0})
    {
        if (!version.Decode(innerDecoder))
            return false;
    }

    if (!serialNumber.Decode(innerDecoder))
        return false;

    if (!signature.Decode(innerDecoder))
        return false;

    if (!issuer.Decode(innerDecoder))
        return false;

    if (!validity.Decode(innerDecoder))
        return false;

    if (!subject.Decode(innerDecoder))
        return false;

    if (!subjectPublicKeyInfo.Decode(innerDecoder))
        return false;

    // The following may not be present, and may need to be skipped
    if (innerDecoder.RemainingData()[0] == std::byte{0xA1})
    {
        if (!issuerUniqueID.Decode(innerDecoder))
            return false;
    }

    if (innerDecoder.RemainingData()[0] == std::byte{0xA2})
    {
        if (!subjectUniqueID.Decode(innerDecoder))
            return false;
    }

    if (innerDecoder.RemainingData()[0] == std::byte{0xA3})
    {
        if (!extensions.Decode(innerDecoder))
            return false;
    }

    return true;
}

void CertificateList::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    tbsCertList.Encode(eh.DataPtr(out));

    signatureAlgorithm.Encode(eh.DataPtr(out));

    signatureValue.Encode(eh.DataPtr(out));
}

bool CertificateList::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertList.Decode(innerDecoder))
        return false;

    if (!signatureAlgorithm.Decode(innerDecoder))
        return false;

    if (!signatureValue.Decode(innerDecoder))
        return false;

    return true;
}

void TBSCertList::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    signature.Encode(eh.DataPtr(out));

    issuer.Encode(eh.DataPtr(out));

    thisUpdate.Encode(eh.DataPtr(out));

    nextUpdate.Encode(eh.DataPtr(out));

    revokedCertificates.Encode(eh.DataPtr(out));

    crlExtensions.Encode(eh.DataPtr(out));
}

bool TBSCertList::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
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
    if (innerDecoder.RemainingData()[0] == static_cast<std::byte>(DerType::Integer))
    {
        if (!version.Decode(innerDecoder))
            return false;
    }

    if (!signature.Decode(innerDecoder))
        return false;

    if (!issuer.Decode(innerDecoder))
        return false;

    if (!thisUpdate.Decode(innerDecoder))
        return false;

    // This is also optional, and may not be present
    if (nextUpdate.Decode(innerDecoder))
    {
    }

    // These are optional, and may not be present
    if (revokedCertificates.Decode(innerDecoder))

        if (decoder.Empty()) // extensions are optional
            return true;

    if (!crlExtensions.Decode(innerDecoder))
        return false;

    return true;
}

void PolicyInformation::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    policyIdentifier.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, policyQualifiers, eh.DataPtr(out));
}

bool PolicyInformation::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyIdentifier.Decode(innerDecoder))
        return false;

    if (decoder.Empty()) // policy qualifiers are optional
        return true;

    size_t cbSize = 0;
    bool ret = decoder.DecodeSequenceOf(cbSize, policyQualifiers);

    if (ret)
    {
        cbData = cbSize;
        // decoder.CurrentSize() = cbSize + cbPrefix;
    }

    return ret;
}

void ESSCertID::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    certHash.Encode(eh.DataPtr(out));

    issuerSerial.Encode(eh.DataPtr(out));
}

bool ESSCertID::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certHash.Decode(innerDecoder))
        return false;

    if (!issuerSerial.Decode(innerDecoder))
        return false;

    return true;
}

void SigningCertificate::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, certs, eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, policies, eh.DataPtr(out));
}

bool SigningCertificate::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!decoder.DecodeSet(certs))
        return false;

    if (!decoder.DecodeSet(policies))
        return false;

    return true;
}

void ESSCertIDv2::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    hashAlgorithm.Encode(eh.DataPtr(out));

    certHash.Encode(eh.DataPtr(out));

    issuerSerial.Encode(eh.DataPtr(out));
}

bool ESSCertIDv2::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(innerDecoder))
        return false;

    if (!certHash.Decode(innerDecoder))
        return false;

    if (!issuerSerial.Decode(innerDecoder))
        return false;

    return true;
}

void PolicyQualifierInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    policyQualifierId.Encode(eh.DataPtr(out));

    qualifier.Encode(eh.DataPtr(out));
}

bool PolicyQualifierInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyQualifierId.Decode(innerDecoder))
        return false;

    if (!qualifier.Decode(innerDecoder))
        return false;

    return true;
}

void IssuerAndSerialNumber::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    issuer.Encode(eh.DataPtr(out));

    serialNumber.Encode(eh.DataPtr(out));
}

bool IssuerAndSerialNumber::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(innerDecoder))
        return false;

    if (!serialNumber.Decode(innerDecoder))
        return false;

    return true;
}

void Extension::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    extnID.Encode(eh.DataPtr(out));

    if (critical.GetValue())
    {
        critical.Encode(eh.DataPtr(out));
    }

    extnValue.Encode(eh.DataPtr(out));
}

bool Extension::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!extnID.Decode(innerDecoder))
        return false;

    // This might not be present
    if (!critical.Decode(innerDecoder))
    {
        // Ought to be false by default, but this is more readable
        critical.SetValue(false);
    }

    if (!extnValue.Decode(innerDecoder))
        return false;

    return true;
}

void CertStatus::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    revoked.Encode(eh.DataPtr(out));
}

bool CertStatus::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revoked.Decode(innerDecoder))
        return false;

    return true;
}

bool DisplayText::Decode(DerDecode& decoder)
{
    if (decoder.RemainingData().size() < 2)
        return false;

// Disable unused enum values warning, it adds a lot of noise here and only specific types are supported
#pragma warning(disable : 4061)
    switch (static_cast<DerType>(decoder.RemainingData()[0]))
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

    return value.Decode(decoder);
}

void SignerInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    sid.Encode(eh.DataPtr(out));

    digestAlgorithm.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, signedAttrs, eh.DataPtr(out));

    signatureAlgorithm.Encode(eh.DataPtr(out));

    signature.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, unsignedAttrs, eh.DataPtr(out));
}

bool SignerInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!sid.Decode(innerDecoder))
        return false;

    if (!digestAlgorithm.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(signedAttrs))
        return false;

    if (!signatureAlgorithm.Decode(innerDecoder))
        return false;

    if (!signature.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(unsignedAttrs))
        return false;

    return true;
}

void OtherCertificateFormat::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    otherCertFormat.Encode(eh.DataPtr(out));

    otherCert.Encode(eh.DataPtr(out));
}

bool OtherCertificateFormat::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertFormat.Decode(innerDecoder))
        return false;

    if (!otherCert.Decode(innerDecoder))
        return false;

    return true;
}

void EDIPartyName::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    nameAssigner.Encode(eh.DataPtr(out));

    partyName.Encode(eh.DataPtr(out));
}

bool EDIPartyName::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!nameAssigner.Decode(innerDecoder))
        return false;

    if (!partyName.Decode(innerDecoder))
        return false;

    return true;
}

void RevocationEntry::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    userCertificate.Encode(eh.DataPtr(out));

    revocationDate.Encode(eh.DataPtr(out));

    crlEntryExtensions.Encode(eh.DataPtr(out));
}

bool RevocationEntry::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
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
    if (innerDecoder.RemainingData()[0] != static_cast<std::byte>(DerType::Integer))
    {
        cbData = 0;
        decoder.Reset(); // This keeps us from throwing
        return false;
    }

    if (!userCertificate.Decode(innerDecoder))
        return false;

    if (!revocationDate.Decode(innerDecoder))
        return false;

    if (decoder.Empty()) // crlEntryExtensions are optional
        return true;

    if (!crlEntryExtensions.Decode(innerDecoder))
        return false;

    return true;
}

void OtherRevocationInfoFormat::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    otherRevInfoFormat.Encode(eh.DataPtr(out));

    otherRevInfo.Encode(eh.DataPtr(out));
}

bool OtherRevocationInfoFormat::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevInfoFormat.Decode(innerDecoder))
        return false;

    if (!otherRevInfo.Decode(innerDecoder))
        return false;

    return true;
}

void SignedData::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, digestAlgorithms, eh.DataPtr(out));

    encapContentInfo.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, crls, eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, signerInfos, eh.DataPtr(out));
}

bool SignedData::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(digestAlgorithms))
        return false;

    if (!encapContentInfo.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(certificates))
        return false;

    if (!decoder.DecodeSet(crls))
        return false;

    if (!decoder.DecodeSet(signerInfos))
        return false;

    return true;
}

void SigPolicyQualifierInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    sigPolicyQualifierId.Encode(eh.DataPtr(out));

    sigQualifier.Encode(eh.DataPtr(out));
}

bool SigPolicyQualifierInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyQualifierId.Decode(innerDecoder))
        return false;

    if (!sigQualifier.Decode(innerDecoder))
        return false;

    return true;
}

void SignaturePolicyId::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    sigPolicyId.Encode(eh.DataPtr(out));

    sigPolicyHash.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, sigPolicyQualifiers, eh.DataPtr(out));
}

bool SignaturePolicyId::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyId.Decode(innerDecoder))
        return false;

    if (!sigPolicyHash.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(sigPolicyQualifiers))
        return false;

    return true;
}

void SPUserNotice::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    noticeRef.Encode(eh.DataPtr(out));

    explicitText.Encode(eh.DataPtr(out));
}

bool SPUserNotice::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(innerDecoder))
        return false;

    if (!explicitText.Decode(innerDecoder))
        return false;

    return true;
}

void CommitmentTypeQualifier::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    commitmentTypeIdentifier.Encode(eh.DataPtr(out));

    qualifier.Encode(eh.DataPtr(out));
}

bool CommitmentTypeQualifier::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeIdentifier.Decode(innerDecoder))
        return false;

    if (!qualifier.Decode(innerDecoder))
        return false;

    return true;
}

void CommitmentTypeIndication::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    commitmentTypeId.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, commitmentTypeQualifier, eh.DataPtr(out));
}

bool CommitmentTypeIndication::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeId.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(commitmentTypeQualifier))
        return false;

    return true;
}

void SignerLocation::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    countryName.Encode(eh.DataPtr(out));

    localityName.Encode(eh.DataPtr(out));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, postalAdddress, eh.DataPtr(out));
}

bool SignerLocation::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!countryName.Decode(innerDecoder))
        return false;

    if (!localityName.Decode(innerDecoder))
        return false;

    if (!decoder.DecodeSet(postalAdddress))
        return false;

    return true;
}

void SignerAttribute::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    EncodeHelper::EncodeSetOrSequenceOf(DerType::ConstructedSet, claimedAttributes, eh.DataPtr(out));

    certifiedAttributes.Encode(eh.DataPtr(out));
}

bool SignerAttribute::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!decoder.DecodeSet(claimedAttributes))
        return false;

    if (!certifiedAttributes.Decode(innerDecoder))
        return false;

    return true;
}

void TimeStampReq::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    messageImprint.Encode(eh.DataPtr(out));

    reqPolicy.Encode(eh.DataPtr(out));

    nonce.Encode(eh.DataPtr(out));

    certReq.Encode(eh.DataPtr(out));

    extensions.Encode(eh.DataPtr(out));
}

bool TimeStampReq::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!messageImprint.Decode(innerDecoder))
        return false;

    if (!reqPolicy.Decode(innerDecoder))
        return false;

    if (!nonce.Decode(innerDecoder))
        return false;

    if (!certReq.Decode(innerDecoder))
        return false;

    if (!extensions.Decode(innerDecoder))
        return false;

    return true;
}

void TimeStampResp::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    status.Encode(eh.DataPtr(out));

    timeStampToken.Encode(eh.DataPtr(out));
}

bool TimeStampResp::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(innerDecoder))
        return false;

    if (!timeStampToken.Decode(innerDecoder))
        return false;

    return true;
}

void TSTInfo::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    version.Encode(eh.DataPtr(out));

    policy.Encode(eh.DataPtr(out));

    messageImprint.Encode(eh.DataPtr(out));

    serialNumber.Encode(eh.DataPtr(out));

    genTime.Encode(eh.DataPtr(out));

    accuracy.Encode(eh.DataPtr(out));

    ordering.Encode(eh.DataPtr(out));

    nonce.Encode(eh.DataPtr(out));

    tsa.Encode(eh.DataPtr(out));

    extensions.Encode(eh.DataPtr(out));
}

bool TSTInfo::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(innerDecoder))
        return false;

    if (!policy.Decode(innerDecoder))
        return false;

    if (!messageImprint.Decode(innerDecoder))
        return false;

    if (!serialNumber.Decode(innerDecoder))
        return false;

    if (!genTime.Decode(innerDecoder))
        return false;

    if (!accuracy.Decode(innerDecoder))
        return false;

    if (!ordering.Decode(innerDecoder))
        return false;

    if (!nonce.Decode(innerDecoder))
        return false;

    if (!tsa.Decode(innerDecoder))
        return false;

    if (!extensions.Decode(innerDecoder))
        return false;

    return true;
}

void OtherCertId::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    otherCertHash.Encode(eh.DataPtr(out));

    issuerSerial.Encode(eh.DataPtr(out));
}

bool OtherCertId::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertHash.Decode(innerDecoder))
        return false;

    if (!issuerSerial.Decode(innerDecoder))
        return false;

    return true;
}

void OcspResponsesID::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    ocspIdentifier.Encode(eh.DataPtr(out));

    ocspRepHash.Encode(eh.DataPtr(out));
}

bool OcspResponsesID::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspIdentifier.Decode(innerDecoder))
        return false;

    if (!ocspRepHash.Decode(innerDecoder))
        return false;

    return true;
}

void Validity::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    notBefore.Encode(eh.DataPtr(out));

    notAfter.Encode(eh.DataPtr(out));
}

bool Validity::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBefore.Decode(innerDecoder))
        return false;

    if (!notAfter.Decode(innerDecoder))
        return false;

    return true;
}

void AttributeTypeAndValue::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    type.Encode(eh.DataPtr(out));

    value.Encode(eh.DataPtr(out));
}

bool AttributeTypeAndValue::Decode(DerDecode& decoder)
{
    DecodeResult result;
    DerDecode innerDecoder;
    std::tie(result, innerDecoder) = decoder.InitSequenceOrSet();
    switch (result)
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!type.Decode(innerDecoder))
        return false;

    if (!value.Decode(innerDecoder))
        return false;

    return true;
}
