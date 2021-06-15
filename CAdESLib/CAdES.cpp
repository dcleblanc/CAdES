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

bool Accuracy::Decode(DerDecode decoder)
{
    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!seconds.Decode(decoder))
        return false;

    if (!millis.Decode(decoder))
        return false;

    if (!micros.Decode(decoder))
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

bool AlgorithmIdentifier::Decode(DerDecode decoder)
{
    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(decoder))
        return false;

    if (decoder.IsAllUsed())
        return true;

    if (!parameters.Decode(decoder))
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

bool Attribute::Decode(DerDecode decoder)
{
    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!attrType.Decode(decoder))
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

bool EncapsulatedContentInfo::Decode(DerDecode decoder)
{
    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!eContentType.Decode(decoder))
        return false;

    
    if (!eContent.Decode(decoder))
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

bool IssuerSerial::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(decoder))
        return false;

    
    if (!serial.Decode(decoder))
        return false;

    
    if (!issuerUID.Decode(decoder))
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

bool ObjectDigestInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!digestedObjectType.Decode(decoder))
        return false;

    
    if (!otherObjectTypeID.Decode(decoder))
        return false;

    
    if (!digestAlgorithm.Decode(decoder))
        return false;

    
    if (!objectDigest.Decode(decoder))
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

bool Holder::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!baseCertificateID.Decode(decoder))
        return false;
    
    if (!entityName.Decode(decoder))
        return false;
    
    if (!objectDigestInfo.Decode(decoder))
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

bool OtherHashAlgAndValue::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(decoder))
        return false;

    
    if (!hashValue.Decode(decoder))
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

bool V2Form::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuerName.Decode(decoder))
        return false;

    
    if (!baseCertificateID.Decode(decoder))
        return false;

    
    if (!objectDigestInfo.Decode(decoder))
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

bool AttCertValidityPeriod::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBeforeTime.Decode(decoder))
        return false;

    
    if (!notAfterTime.Decode(decoder))
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

bool AttributeCertificateInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!holder.Decode(decoder))
        return false;

    
    if (!issuer.Decode(decoder))
        return false;

    
    if (!holder.Decode(decoder))
        return false;

    
    if (!signature.Decode(decoder))
        return false;

    
    if (!serialNumber.Decode(decoder))
        return false;

    
    if (!attrCertValidityPeriod.Decode(decoder))
        return false;

    
    if (!decoder.DecodeSet(attributes))
        return false;

    
    if (!issuerUniqueID.Decode(decoder))
        return false;

    
    if (!extensions.Decode(decoder))
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

bool AttributeCertificate::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!acinfo.Decode(decoder))
        return false;

    
    if (!signatureAlgorithm.Decode(decoder))
        return false;

    
    if (!signatureValue.Decode(decoder))
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

bool CertID::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(decoder))
        return false;

    
    if (!issuerNameHash.Decode(decoder))
        return false;

    
    if (!issuerKeyHash.Decode(decoder))
        return false;

    
    if (!serialNumber.Decode(decoder))
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

bool RevokedInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revocationTime.Decode(decoder))
        return false;

    
    if (!revocationReason.Decode(decoder))
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

bool SingleResponse::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certID.Decode(decoder))
        return false;

    
    if (!certStatus.Decode(decoder))
        return false;

    
    if (!thisUpdate.Decode(decoder))
        return false;

    
    if (!nextUpdate.Decode(decoder))
        return false;

    
    if (!singleExtensions.Decode(decoder))
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

bool PKIStatusInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(decoder))
        return false;

    
    if (!statusString.Decode(decoder))
        return false;

    
    if (!failInfo.Decode(decoder))
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

bool ContentInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!contentType.Decode(decoder))
        return false;

    
    if (!content.Decode(decoder))
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

bool CrlIdentifier::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlissuer.Decode(decoder))
        return false;

    
    if (!crlIssuedTime.Decode(decoder))
        return false;

    
    if (!crlNumber.Decode(decoder))
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

bool CrlValidatedID::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!crlHash.Decode(decoder))
        return false;

    
    if (!crlIdentifier.Decode(decoder))
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

bool MessageImprint::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(decoder))
        return false;

    
    if (!hashedMessage.Decode(decoder))
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

bool UserNotice::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(decoder))
        return false;

    
    if (!explicitText.Decode(decoder))
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

bool NoticeReference::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!organization.Decode(decoder))
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

bool OcspIdentifier::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspResponderID.Decode(decoder))
        return false;

    
    if (!producedAt.Decode(decoder))
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

bool CrlOcspRef::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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

    
    if (!ocspids.Decode(decoder))
        return false;

    
    if (!otherRev.Decode(decoder))
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

bool OtherRevRefs::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevRefType.Decode(decoder))
        return false;

    
    if (!otherRevRefs.Decode(decoder))
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

bool RevocationValues::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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

    
    if (!otherRevVals.Decode(decoder))
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

bool OtherRevVals::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevValType.Decode(decoder))
        return false;

    
    if (!otherRevVals.Decode(decoder))
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

bool BasicOCSPResponse::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsResponseData.Decode(decoder))
        return false;

    
    if (!signatureAlgorithm.Decode(decoder))
        return false;

    
    if (!signature.Decode(decoder))
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

bool ResponseData::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!responderID.Decode(decoder))
        return false;

    
    if (!producedAt.Decode(decoder))
        return false;

    
    if (!decoder.DecodeSet(responses))
        return false;

    
    if (!extensions.Decode(decoder))
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

bool SigningCertificateV2::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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

bool SubjectPublicKeyInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!algorithm.Decode(decoder))
        return false;

    
    if (!subjectPublicKey.Decode(decoder))
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

bool Certificate::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertificate.Decode(decoder))
        return false;

    
    if (!signatureAlgorithm.Decode(decoder))
        return false;

    
    if (!signatureValue.Decode(decoder))
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

bool TBSCertificate::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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
    if (decoder.RemainingData()[0] == std::byte{0xA0})
    {
        if (!version.Decode(decoder))
            return false;
    }

    
    if (!serialNumber.Decode(decoder))
        return false;

    
    if (!signature.Decode(decoder))
        return false;

    
    if (!issuer.Decode(decoder))
        return false;

    
    if (!validity.Decode(decoder))
        return false;

    
    if (!subject.Decode(decoder))
        return false;

    
    if (!subjectPublicKeyInfo.Decode(decoder))
        return false;

    
    // The following may not be present, and may need to be skipped
    if (decoder.RemainingData()[0] == std::byte{0xA1})
    {
        if (!issuerUniqueID.Decode(decoder))
            return false;

        
    }

    if (decoder.RemainingData()[0] == std::byte{0xA2})
    {
        if (!subjectUniqueID.Decode(decoder))
            return false;

        
    }

    if (decoder.RemainingData()[0] == std::byte{0xA3})
    {
        if (!extensions.Decode(decoder))
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

bool CertificateList::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!tbsCertList.Decode(decoder))
        return false;

    
    if (!signatureAlgorithm.Decode(decoder))
        return false;

    
    if (!signatureValue.Decode(decoder))
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

bool TBSCertList::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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
    if (decoder.RemainingData()[0] == static_cast<std::byte>(DerType::Integer))
    {
        if (!version.Decode(decoder))
            return false;

        
    }

    if (!signature.Decode(decoder))
        return false;

    
    if (!issuer.Decode(decoder))
        return false;

    
    if (!thisUpdate.Decode(decoder))
        return false;

    

    // This is also optional, and may not be present
    if (nextUpdate.Decode(decoder))
    {
        
    }

    // These are optional, and may not be present
    if (revokedCertificates.Decode(decoder))
        

    if (decoder.IsAllUsed()) // extensions are optional
        return true;

    if (!crlExtensions.Decode(decoder))
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

bool PolicyInformation::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyIdentifier.Decode(decoder))
        return false;

    
    if (decoder.IsAllUsed()) // policy qualifiers are optional
        return true;

    size_t cbSize = 0;
    size_t cbPrefix = 0;
    bool ret = decoder.DecodeSequenceOf(cbPrefix, cbSize, policyQualifiers);

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

bool ESSCertID::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!certHash.Decode(decoder))
        return false;

    
    if (!issuerSerial.Decode(decoder))
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

bool SigningCertificate::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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

bool ESSCertIDv2::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!hashAlgorithm.Decode(decoder))
        return false;

    
    if (!certHash.Decode(decoder))
        return false;

    
    if (!issuerSerial.Decode(decoder))
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

bool PolicyQualifierInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!policyQualifierId.Decode(decoder))
        return false;

    
    if (!qualifier.Decode(decoder))
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

bool IssuerAndSerialNumber::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!issuer.Decode(decoder))
        return false;

    

    if (!serialNumber.Decode(decoder))
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

bool Extension::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!extnID.Decode(decoder))
        return false;

    
    // This might not be present
    if (!critical.Decode(decoder))
    {
        // Ought to be false by default, but this is more readable
        critical.SetValue(false);
    }

    
    if (!extnValue.Decode(decoder))
        return false;

    return true;
}

void CertStatus::Encode(std::span<std::byte> out)
{
    EncodeHelper eh(out);

    eh.Init(out.size(), static_cast<std::byte>(DerType::ConstructedSequence));

    revoked.Encode(eh.DataPtr(out));
}

bool CertStatus::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!revoked.Decode(decoder))
        return false;

    return true;
}

bool DisplayText::Decode(DerDecode decoder)
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

bool SignerInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!sid.Decode(decoder))
        return false;

    
    if (!digestAlgorithm.Decode(decoder))
        return false;

    
    if (!decoder.DecodeSet(signedAttrs))
        return false;

    
    if (!signatureAlgorithm.Decode(decoder))
        return false;

    
    if (!signature.Decode(decoder))
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

bool OtherCertificateFormat::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertFormat.Decode(decoder))
        return false;

    
    if (!otherCert.Decode(decoder))
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

bool EDIPartyName::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!nameAssigner.Decode(decoder))
        return false;

    
    if (!partyName.Decode(decoder))
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

bool RevocationEntry::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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
    if (decoder.RemainingData()[0] != static_cast<std::byte>(DerType::Integer))
    {
        cbData = 0;
        decoder.Reset(); // This keeps us from throwing
        return false;
    }

    if (!userCertificate.Decode(decoder))
        return false;

    
    if (!revocationDate.Decode(decoder))
        return false;

    

    if (decoder.IsAllUsed()) // crlEntryExtensions are optional
        return true;

    if (!crlEntryExtensions.Decode(decoder))
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

bool OtherRevocationInfoFormat::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherRevInfoFormat.Decode(decoder))
        return false;

    
    if (!otherRevInfo.Decode(decoder))
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

bool SignedData::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!decoder.DecodeSet(digestAlgorithms))
        return false;

    
    if (!encapContentInfo.Decode(decoder))
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

bool SigPolicyQualifierInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyQualifierId.Decode(decoder))
        return false;

    
    if (!sigQualifier.Decode(decoder))
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

bool SignaturePolicyId::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!sigPolicyId.Decode(decoder))
        return false;

    
    if (!sigPolicyHash.Decode(decoder))
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

bool SPUserNotice::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!noticeRef.Decode(decoder))
        return false;

    
    if (!explicitText.Decode(decoder))
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

bool CommitmentTypeQualifier::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeIdentifier.Decode(decoder))
        return false;

    
    if (!qualifier.Decode(decoder))
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

bool CommitmentTypeIndication::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!commitmentTypeId.Decode(decoder))
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

bool SignerLocation::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!countryName.Decode(decoder))
        return false;

    
    if (!localityName.Decode(decoder))
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

bool SignerAttribute::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
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

    
    if (!certifiedAttributes.Decode(decoder))
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

bool TimeStampReq::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!messageImprint.Decode(decoder))
        return false;

    
    if (!reqPolicy.Decode(decoder))
        return false;

    
    if (!nonce.Decode(decoder))
        return false;

    
    if (!certReq.Decode(decoder))
        return false;

    
    if (!extensions.Decode(decoder))
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

bool TimeStampResp::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!status.Decode(decoder))
        return false;

    
    if (!timeStampToken.Decode(decoder))
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

bool TSTInfo::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!version.Decode(decoder))
        return false;

    
    if (!policy.Decode(decoder))
        return false;

    
    if (!messageImprint.Decode(decoder))
        return false;

    
    if (!serialNumber.Decode(decoder))
        return false;

    
    if (!genTime.Decode(decoder))
        return false;

    
    if (!accuracy.Decode(decoder))
        return false;

    
    if (!ordering.Decode(decoder))
        return false;

    
    if (!nonce.Decode(decoder))
        return false;

    
    if (!tsa.Decode(decoder))
        return false;

    
    if (!extensions.Decode(decoder))
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

bool OtherCertId::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!otherCertHash.Decode(decoder))
        return false;

    
    if (!issuerSerial.Decode(decoder))
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

bool OcspResponsesID::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!ocspIdentifier.Decode(decoder))
        return false;

    
    if (!ocspRepHash.Decode(decoder))
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

bool Validity::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!notBefore.Decode(decoder))
        return false;

    
    if (!notAfter.Decode(decoder))
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

bool AttributeTypeAndValue::Decode(DerDecode decoder)
{
    

    switch (decoder.InitSequenceOrSet())
    {
    case DecodeResult::Failed:
        return false;
    case DecodeResult::Null:
    case DecodeResult::EmptySequence:
        return true;
    case DecodeResult::Success:
        break;
    }

    if (!type.Decode(decoder))
        return false;

    
    if (!value.Decode(decoder))
        return false;

    return true;
}
