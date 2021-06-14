// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Oids.h"

#include "Common.h"
#include "DerTypes.h"

#define REGENERATE_TABLE
#ifdef REGENERATE_TABLE

struct OidAndPtr
{
    std::string oid;
    std::string varname;
};

std::array knownOids =
    {
        OidAndPtr{id_at, "id_at"},
        OidAndPtr{id_at_surname, "id_at_surname"},
        OidAndPtr{id_at_name, "id_at_name"},
        OidAndPtr{id_at_givenName, "id_at_givenName"},
        OidAndPtr{id_at_initials, "id_at_initials"},
        OidAndPtr{id_at_generationQualifier, "id_at_generationQualifier"},
        OidAndPtr{id_at_commonName, "id_at_commonName"},
        OidAndPtr{id_at_serialNumber, "id_at_serialNumber"},
        OidAndPtr{id_at_countryName, "id_at_countryName"},
        OidAndPtr{id_at_localityName, "id_at_localityName"},
        OidAndPtr{id_at_stateOrProvinceName, "id_at_stateOrProvinceName"},
        OidAndPtr{id_at_streetAddress, "id_at_streetAddress"},
        OidAndPtr{id_at_organizationName, "id_at_organizationName"},
        OidAndPtr{id_at_organizationUnitName, "id_at_organizationUnitName"},
        OidAndPtr{id_at_title, "id_at_title"},
        OidAndPtr{id_at_distinguishedName, "id_at_distinguishedName"},
        OidAndPtr{id_at_pseudonym, "id_at_pseudonym"},
        OidAndPtr{id_ce, "id_ce"},
        OidAndPtr{id_ce_subjectDirectoryAttributes, "id_ce_subjectDirectoryAttributes"},
        OidAndPtr{id_ce_subjectKeyIdentifier, "id_ce_subjectKeyIdentifier"},
        OidAndPtr{id_ce_keyUsage, "id_ce_keyUsage"},
        OidAndPtr{id_ce_privateKeyUsagePeriod, "id_ce_privateKeyUsagePeriod"},
        OidAndPtr{id_ce_subjectAltName, "id_ce_subjectAltName"},
        OidAndPtr{id_ce_issuerAltName, "id_ce_issuerAltName"},
        OidAndPtr{id_ce_basicConstraints, "id_ce_basicConstraints"},
        OidAndPtr{id_ce_cRLNumber, "id_ce_cRLNumber"},
        OidAndPtr{id_ce_cRLReasons, "id_ce_cRLReasons"},
        OidAndPtr{id_ce_holdInstructionCode, "id_ce_holdInstructionCode"},
        OidAndPtr{id_ce_invalidityDate, "id_ce_invalidityDate"},
        OidAndPtr{id_ce_deltaCRLIndicator, "id_ce_deltaCRLIndicator"},
        OidAndPtr{id_ce_issuingDistributionPoint, "id_ce_issuingDistributionPoint"},
        OidAndPtr{id_ce_certificateIssuer, "id_ce_certificateIssuer"},
        OidAndPtr{id_ce_nameConstraints, "id_ce_nameConstraints"},
        OidAndPtr{id_ce_cRLDistributionPoints, "id_ce_cRLDistributionPoints"},
        OidAndPtr{id_ce_certificatePolicies, "id_ce_certificatePolicies"},
        OidAndPtr{id_ce_certificatePolicies_anyPolicy, "id_ce_certificatePolicies_anyPolicy"},
        OidAndPtr{id_ce_policyMappings, "id_ce_policyMappings"},
        OidAndPtr{id_ce_authorityKeyIdentifier_old, "id_ce_authorityKeyIdentifier_old"},
        OidAndPtr{id_ce_policyConstraints, "id_ce_policyConstraints"},
        OidAndPtr{id_ce_extKeyUsage, "id_ce_extKeyUsage"},
        OidAndPtr{id_ce_extKeyUsage_any, "id_ce_extKeyUsage_any"},
        OidAndPtr{id_ce_freshestCRL, "id_ce_freshestCRL"},
        OidAndPtr{id_ce_inhibitAnyPolicy, "id_ce_inhibitAnyPolicy"},
        OidAndPtr{id_holdInstruction, "id_holdInstruction"},
        OidAndPtr{id_holdInstruction_none, "id_holdInstruction_none"},
        OidAndPtr{id_holdInstruction_callissuer, "id_holdInstruction_callissuer"},
        OidAndPtr{id_holdInstruction_reject, "id_holdInstruction_reject"},
        OidAndPtr{id_pkix, "id_pkix"},
        OidAndPtr{id_pe, "id_pe"},
        OidAndPtr{id_qt, "id_qt"},
        OidAndPtr{id_kp, "id_kp"},
        OidAndPtr{id_ad, "id_ad"},
        OidAndPtr{id_pe_authorityInfoAccess, "id_pe_authorityInfoAccess"},
        OidAndPtr{id_pe_subjectInfoAccess, "id_pe_subjectInfoAccess"},
        OidAndPtr{id_qt_cps, "id_qt_cps"},
        OidAndPtr{id_qt_unotice, "id_qt_unotice"},
        OidAndPtr{id_kp_serverAuth, "id_kp_serverAuth"},
        OidAndPtr{id_kp_clientAuth, "id_kp_clientAuth"},
        OidAndPtr{id_kp_codeSigning, "id_kp_codeSigning"},
        OidAndPtr{id_kp_emailProtection, "id_kp_emailProtection"},
        OidAndPtr{id_kp_timeStamping, "id_kp_timeStamping"},
        OidAndPtr{id_kp_OCSPSigning, "id_kp_OCSPSigning"},
        OidAndPtr{id_ad_ocsp, "id_ad_ocsp"},
        OidAndPtr{id_ad_caIssuers, "id_ad_caIssuers"},
        OidAndPtr{id_ad_timeStamping, "id_ad_timeStamping"},
        OidAndPtr{id_ad_caRepository, "id_ad_caRepository"},
        OidAndPtr{pkcs_9, "pkcs_9"},
        OidAndPtr{id_emailAddress, "id_emailAddress"},
        OidAndPtr{id_data, "id_data"},
        OidAndPtr{id_signedData, "id_signedData"},
        OidAndPtr{id_contentType, "id_contentType"},
        OidAndPtr{id_messageDigest, "id_messageDigest"},
        OidAndPtr{id_signingTime, "id_signingTime"},
        OidAndPtr{id_countersignature, "id_countersignature"},
        OidAndPtr{id_aa_signingCertificate, "id_aa_signingCertificate"},
        OidAndPtr{id_aa_signingCertificateV2, "id_aa_signingCertificateV2"},
        OidAndPtr{id_md2, "id_md2"},
        OidAndPtr{id_md5, "id_md5"},
        OidAndPtr{id_sha1, "id_sha1"},
        OidAndPtr{id_sha256, "id_sha256"},
        OidAndPtr{id_sha384, "id_sha384"},
        OidAndPtr{id_sha512, "id_sha512"},
        OidAndPtr{id_sha224, "id_sha224"},
        OidAndPtr{id_sha512_224, "id_sha512_224"},
        OidAndPtr{id_sha512_256, "id_sha512_256"},
        OidAndPtr{id_sha3_224, "id_sha3_224"},
        OidAndPtr{id_sha3_256, "id_sha3_256"},
        OidAndPtr{id_sha3_384, "id_sha3_384"},
        OidAndPtr{id_sha3_512, "id_sha3_512"},
        OidAndPtr{id_shake_128, "id_shake_128"},
        OidAndPtr{id_shake_256, "id_shake_256"},
        OidAndPtr{id_pkcs_1, "id_pkcs_1"},
        OidAndPtr{id_rsaEncryption, "id_rsaEncryption"},
        OidAndPtr{id_md2WithRSAEncryption, "id_md2WithRSAEncryption"},
        OidAndPtr{id_md5WithRSAEncryption, "id_md5WithRSAEncryption"},
        OidAndPtr{id_sha1WithRSAEncryption, "id_sha1WithRSAEncryption"},
        OidAndPtr{id_sha256WithRSAEncryption, "id_sha256WithRSAEncryption"},
        OidAndPtr{id_sha384WithRSAEncryption, "id_sha384WithRSAEncryption"},
        OidAndPtr{id_sha512WithRSAEncryption, "id_sha512WithRSAEncryption"},
        OidAndPtr{id_sha224WithRSAEncryption, "id_sha224WithRSAEncryption"},
        OidAndPtr{id_dsa_with_sha1, "id_dsa_with_sha1"},
        OidAndPtr{ansi_X9_62, "ansi_X9_62"},
        OidAndPtr{id_ecSigType, "id_ecSigType"},
        OidAndPtr{id_ecdsa_with_SHA1, "id_ecdsa_with_SHA1"},
        OidAndPtr{id_ecdsa_with_SHA224, "id_ecdsa_with_SHA224"},
        OidAndPtr{id_ecdsa_with_SHA256, "id_ecdsa_with_SHA256"},
        OidAndPtr{id_ecdsa_with_SHA384, "id_ecdsa_with_SHA384"},
        OidAndPtr{id_ecdsa_with_SHA512, "id_ecdsa_with_SHA512"},
        OidAndPtr{id_pilot_userid, "id_pilot_userid"},
        OidAndPtr{id_pilot_domainComponent, "id_pilot_domainComponent"},
        OidAndPtr{id_entrustVersInfo, "id_entrustVersInfo"},
        OidAndPtr{id_cti_ets_proofOfOrigin, "id_cti_ets_proofOfOrigin"},
        OidAndPtr{id_cti_ets_proofOfReceipt, "id_cti_ets_proofOfReceipt"},
        OidAndPtr{id_cti_ets_proofOfDelivery, "id_cti_ets_proofOfDelivery"},
        OidAndPtr{id_cti_ets_proofOfSender, "id_cti_ets_proofOfSender"},
        OidAndPtr{id_cti_ets_proofOfApproval, "id_cti_ets_proofOfApproval"},
        OidAndPtr{id_cti_ets_proofOfCreation, "id_cti_ets_proofOfCreation"},
        OidAndPtr{id_smimeCapabilities, "id_smimeCapabilities"},
        OidAndPtr{id_mgf1, "id_mgf1"},
        OidAndPtr{rsassa_pss, "rsassa_pss"},
        OidAndPtr{id_apple_pushDev, "id_apple_pushDev"},
        OidAndPtr{id_apple_pushProd, "id_apple_pushProd"},
        OidAndPtr{id_apple_custom6, "id_apple_custom6"},
        OidAndPtr{id_sha1WithRSASignature, "id_sha1WithRSASignature"},
        OidAndPtr{id_google_certTransparancy, "id_google_certTransparancy"},
        OidAndPtr{id_microsoft_certFriendlyName, "id_microsoft_certFriendlyName"},
        OidAndPtr{id_microsoft_enrollCertType, "id_microsoft_enrollCertType"},
        OidAndPtr{id_microsoft_certsrvCAVersion, "id_microsoft_certsrvCAVersion"},
        OidAndPtr{id_microsoft_jurisdictionOfIncorporationCountryName, "id_microsoft_jurisdictionOfIncorporationCountryName"},
        OidAndPtr{id_netscape_certExt, "id_netscape_certExt"},
        OidAndPtr{id_ce_authorityKeyIdentifier, "id_ce_authorityKeyIdentifier"},
        OidAndPtr{id_ce_keyUsageRestriction, "id_ce_keyUsageRestriction"},
        OidAndPtr{id_at_businessCategory, "id_at_businessCategory"},
        OidAndPtr{id_at_postalCode, "id_at_postalCode"},
        OidAndPtr{id_microsoft_appCertPolicies, "id_microsoft_appCertPolicies"},
        OidAndPtr{id_microsoft_certsrvPrevHash, "id_microsoft_certsrvPrevHash"},
        OidAndPtr{id_microsoft_certTemplate, "id_microsoft_certTemplate"},
};

class OidHelper
{
public:
    std::string oid;
    std::span<const std::byte> encodedOid; // ASN.1 encoding
    std::string textOid;         // Friendly name
    std::string varName;
};

#include <map>
#include <stdio.h>
void PrintOids()
{
    // This is all terribly inefficient, but is only used
    // to create the structure definition we need
    typedef std::vector<uint8_t> oidBytes;
    std::map<oidBytes, OidHelper> oidMap;
    size_t maxKeylen = 0;
    std::byte keybuf[12];

    for (size_t i = 0; i < knownOids.size(); ++i)
    {
        ObjectIdentifier oi;
        oi.SetValue(knownOids[i].oid);

        auto keyBytes = oi.GetBytes();
        auto pKeyBytes = reinterpret_cast<const uint8_t *>(keyBytes.data());
        oidBytes key{pKeyBytes, pKeyBytes + keyBytes.size()};
        OidHelper hlp;

        if (key.size() > maxKeylen)
            maxKeylen = key.size();

        hlp.oid = knownOids[i].oid;
        hlp.textOid = "";
        hlp.varName = knownOids[i].varname;

        oidMap[key] = hlp;
    }

    // We now have a sorted map of these
    // Print this out as:
    // { key, variable name },
    // Where key is { 0xaa, 0xbb, 0xcc }
    std::map<oidBytes, OidHelper>::iterator it = oidMap.begin();

    printf("{ \n");
    for (; it != oidMap.end(); ++it)
    {
        const oidBytes &key = (*it).first;
        const OidHelper &oh = (*it).second;

        memset(keybuf, 0, sizeof(keybuf));
        memcpy_s(keybuf, sizeof(keybuf), &key[0], key.size());
        keybuf[sizeof(keybuf) - 1] = static_cast<std::byte>(key.size());

        printf("\t{ { 0x%02x, ", (std::byte)keybuf[0]);
        for (uint32_t i = 1; i < sizeof(keybuf) - 1; ++i)
        {
            printf("0x%02x, ", (std::byte)keybuf[i]);
        }
        printf("0x%02x }, ", (std::byte)keybuf[sizeof(keybuf) - 1]);
        printf("%s, ", oh.varName.c_str());
        printf("\"\" },\n");
    }
    printf("} \n");
}
#else
void PrintOids() {}
#endif

namespace
{

    struct OidInfo
    {
        std::array<std::byte, 12> encodedOid;
        std::string oid;
        std::string szOidLabel;
    };

    // Note - last byte is the number of octets used
    // This disambiguates 1.2.3.4 and 1.2.3.4.0
    std::array oidTable =
        {
            OidInfo{make_bytes(0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01, 0x00, 0x0a), id_pilot_userid, "pilot_userid"},
            OidInfo{make_bytes(0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x00, 0x0a), id_pilot_domainComponent, "pilot_domainComponent"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x41, 0x00, 0x00, 0x00, 0x09), id_entrustVersInfo, "entrustVersInfo"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08), id_pkcs_1, "PKCS1"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x00, 0x00, 0x09), id_rsaEncryption, "RSA Encryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02, 0x00, 0x00, 0x09), id_md2WithRSAEncryption, "md2WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x00, 0x00, 0x09), id_md5WithRSAEncryption, "md5WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x00, 0x00, 0x09), id_sha1WithRSASignature, "id_sha1WithRSASignature"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x00, 0x00, 0x09), id_mgf1, "mgf1"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x00, 0x00, 0x09), rsassa_pss, "rsassa_pss"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x00, 0x00, 0x09), id_sha256WithRSAEncryption, "sha256WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x00, 0x00, 0x09), id_sha384WithRSAEncryption, "sha384WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x00, 0x00, 0x09), id_sha512WithRSAEncryption, "sha512WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e, 0x00, 0x00, 0x09), id_sha224WithRSAEncryption, "sha224WithRSAEncryption"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x00, 0x00, 0x09), id_data, "data"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0x00, 0x00, 0x09), id_signedData, "signedData"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x00, 0x00, 0x00, 0x08), pkcs_9, "PKCS9"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x00, 0x00, 0x09), id_emailAddress, "emailAddress"}, // Deprecated, use altName extension
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x00, 0x00, 0x09), id_contentType, "contentType"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x00, 0x00, 0x09), id_messageDigest, "messageDigest"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x00, 0x00, 0x09), id_signingTime, "signingTime"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06, 0x00, 0x00, 0x09), id_countersignature, "countersignature"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x00, 0x00, 0x09), id_smimeCapabilities, "smimeCapabilities"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x00, 0x0a), id_cti_ets_proofOfOrigin, "cti_ets_proofOfOrigin"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x00, 0x0a), id_cti_ets_proofOfReceipt, "cti_ets_proofOfReceipt"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c, 0x0b), id_aa_signingCertificate, "signingCertificate"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f, 0x0b), id_aa_signingCertificateV2, "signingCertificateV2"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x00, 0x0a), id_cti_ets_proofOfDelivery, "cti_ets_proofOfDelivery"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x04, 0x00, 0x0a), id_cti_ets_proofOfSender, "cti_ets_proofOfSender"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x05, 0x00, 0x0a), id_cti_ets_proofOfApproval, "cti_ets_proofOfApproval"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x00, 0x0a), id_cti_ets_proofOfCreation, "cti_ets_proofOfCreation"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x00, 0x00, 0x00, 0x08), id_md2, "md2"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x00, 0x00, 0x00, 0x08), id_md5, "md5"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x01, 0x00, 0x0a), id_apple_pushDev, "apple_pushDev"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x02, 0x00, 0x0a), id_apple_pushProd, "apple_pushProd"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x06, 0x00, 0x0a), id_apple_custom6, "apple_custom6"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06), id_holdInstruction, "holdInstruction"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07), id_holdInstruction_none, "holdInstruction_none"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07), id_holdInstruction_callissuer, "holdInstruction_callissuer"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07), id_holdInstruction_reject, "holdInstruction_reject"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07), id_dsa_with_sha1, "dsa_with_sha1"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05), ansi_X9_62, "ECDSA"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06), id_ecSigType, "ECDSA_signature"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07), id_ecdsa_with_SHA1, "ecdsa_with_SHA1"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08), id_ecdsa_with_SHA224, "ecdsa_with_SHA224"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08), id_ecdsa_with_SHA256, "ecdsa_with_SHA256"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x00, 0x00, 0x00, 0x08), id_ecdsa_with_SHA384, "ecdsa_with_SHA384"},
            OidInfo{make_bytes(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x00, 0x00, 0x00, 0x08), id_ecdsa_with_SHA512, "ecdsa_with_SHA512"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x0b, 0x0b, 0x00, 0x0a), id_microsoft_certFriendlyName, "microsoft_certFriendlyName"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x00, 0x00, 0x09), id_microsoft_enrollCertType, "microsoft_enrollCertType"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01, 0x00, 0x00, 0x09), id_microsoft_certsrvCAVersion, "microsoft_certsrvCAVersion"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x02, 0x00, 0x00, 0x09), id_microsoft_certsrvPrevHash, "microsoft_certsrvPrevHash"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x04, 0x00, 0x00, 0x09), id_microsoft_certsrvnNextPublish, "microsoft_certsrvnNextPublish"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07, 0x00, 0x00, 0x09), id_microsoft_certTemplate, "microsoft_certTemplate"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0a, 0x00, 0x00, 0x09), id_microsoft_appCertPolicies, "microsoft_appCertPolicies"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03, 0x0b), id_microsoft_jurisdictionOfIncorporationCountryName, "microsoft_jurisdictionOfIncorporationCountryName"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02, 0x00, 0x0a), id_google_certTransparancy, "google_certTransparancy"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06), id_pkix, "PKIX"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07), id_pe, "Private extensions"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08), id_pe_authorityInfoAccess, "authorityInfoAccess"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x08), id_pe_subjectInfoAccess, "subjectInfoAccess"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07), id_qt, "qt"}, // (PKIX) policy qualifier types
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x00, 0x00, 0x00, 0x08), id_qt_cps, "qt_cps"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x00, 0x00, 0x00, 0x08), id_qt_unotice, "unotice"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07), id_kp, "kp"}, // Extended Key Purposes
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08), id_kp_serverAuth, "serverAuth"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08), id_kp_clientAuth, "clientAuth"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x00, 0x00, 0x00, 0x08), id_kp_codeSigning, "codeSigning"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x00, 0x00, 0x00, 0x08), id_kp_emailProtection, "emailProtection"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x00, 0x00, 0x00, 0x08), id_kp_timeStamping, "timeStamping"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x00, 0x00, 0x00, 0x08), id_kp_OCSPSigning, "OCSPSigning"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x00, 0x00, 0x00, 0x00, 0x07), id_ad, "ad"}, // Access descriptors
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x00, 0x00, 0x00, 0x08), id_ad_ocsp, "ocsp"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x00, 0x00, 0x00, 0x08), id_ad_caIssuers, "caIssuers"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x03, 0x00, 0x00, 0x00, 0x08), id_ad_timeStamping, "timeStamping"},
            OidInfo{make_bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, 0x00, 0x00, 0x00, 0x08), id_ad_caRepository, "caRepository"},
            OidInfo{make_bytes(0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05), id_sha1, "sha1"},
            OidInfo{make_bytes(0x2b, 0x0e, 0x03, 0x02, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05), id_sha1WithRSAEncryption, "sha1WithRSAEncryption"},
            OidInfo{make_bytes(0x55, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02), id_at, "at"}, // Attribute types
            OidInfo{make_bytes(0x55, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_commonName, "commonName"},
            OidInfo{make_bytes(0x55, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_surname, "surname"},
            OidInfo{make_bytes(0x55, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_serialNumber, "serialNumber"},
            OidInfo{make_bytes(0x55, 0x04, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_countryName, "countryName"},
            OidInfo{make_bytes(0x55, 0x04, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_localityName, "localityName"},
            OidInfo{make_bytes(0x55, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_stateOrProvinceName, "stateOrProvinceName"},
            OidInfo{make_bytes(0x55, 0x04, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_streetAddress, "streetAddress"},
            OidInfo{make_bytes(0x55, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_organizationName, "organizationName"},
            OidInfo{make_bytes(0x55, 0x04, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_organizationUnitName, "organizationUnitName"},
            OidInfo{make_bytes(0x55, 0x04, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_title, "title"},
            OidInfo{make_bytes(0x55, 0x04, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_businessCategory, "businessCategory"},
            OidInfo{make_bytes(0x55, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_postalCode, "postalCode"},
            OidInfo{make_bytes(0x55, 0x04, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_name, "name"},
            OidInfo{make_bytes(0x55, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_givenName, "givenName"},
            OidInfo{make_bytes(0x55, 0x04, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_initials, "initials"},
            OidInfo{make_bytes(0x55, 0x04, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_generationQualifier, "generationQualifier"},
            OidInfo{make_bytes(0x55, 0x04, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_distinguishedName, "distinguishedName"},
            OidInfo{make_bytes(0x55, 0x04, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_at_pseudonym, "pseudonym"},
            OidInfo{make_bytes(0x55, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02), id_ce, "ce"}, // Certificate extension
            OidInfo{make_bytes(0x55, 0x1d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_authorityKeyIdentifier_old, "authorityKeyIdentifier_old"},
            OidInfo{make_bytes(0x55, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_keyUsageRestriction, "keyUsageRestriction"},
            OidInfo{make_bytes(0x55, 0x1d, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_subjectDirectoryAttributes, "subjectDirectoryAttributes"},
            OidInfo{make_bytes(0x55, 0x1d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_subjectKeyIdentifier, "subjectKeyIdentifier"},
            OidInfo{make_bytes(0x55, 0x1d, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_keyUsage, "keyUsage"},
            OidInfo{make_bytes(0x55, 0x1d, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_privateKeyUsagePeriod, "privateKeyUsagePeriod"},
            OidInfo{make_bytes(0x55, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_subjectAltName, "subjectAltName"},
            OidInfo{make_bytes(0x55, 0x1d, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_issuerAltName, "issuerAltName"},
            OidInfo{make_bytes(0x55, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_basicConstraints, "basicConstraints"},
            OidInfo{make_bytes(0x55, 0x1d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_cRLNumber, "cRLNumber"},
            OidInfo{make_bytes(0x55, 0x1d, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_cRLReasons, "cRLReasons"},
            OidInfo{make_bytes(0x55, 0x1d, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_holdInstructionCode, "holdInstructionCode"},
            OidInfo{make_bytes(0x55, 0x1d, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_invalidityDate, "invalidityDate"},
            OidInfo{make_bytes(0x55, 0x1d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_deltaCRLIndicator, "deltaCRLIndicator"},
            OidInfo{make_bytes(0x55, 0x1d, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_issuingDistributionPoint, "issuingDistributionPoint"},
            OidInfo{make_bytes(0x55, 0x1d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_certificateIssuer, "certificateIssuer"},
            OidInfo{make_bytes(0x55, 0x1d, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_nameConstraints, "nameConstraints"},
            OidInfo{make_bytes(0x55, 0x1d, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_cRLDistributionPoints, "cRLDistributionPoints"},
            OidInfo{make_bytes(0x55, 0x1d, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_certificatePolicies, "certificatePolicies"},
            OidInfo{make_bytes(0x55, 0x1d, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04), id_ce_certificatePolicies_anyPolicy, "certificatePolicies_anyPolicy"},
            OidInfo{make_bytes(0x55, 0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_policyMappings, "policyMappings"},
            OidInfo{make_bytes(0x55, 0x1d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_authorityKeyIdentifier, "authorityKeyIdentifier"},
            OidInfo{make_bytes(0x55, 0x1d, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_policyConstraints, "policyConstraints"},
            OidInfo{make_bytes(0x55, 0x1d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_extKeyUsage, "extKeyUsage"},
            OidInfo{make_bytes(0x55, 0x1d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04), id_ce_extKeyUsage_any, "extKeyUsage_any"},
            OidInfo{make_bytes(0x55, 0x1d, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_freshestCRL, "freshestCRL"},
            OidInfo{make_bytes(0x55, 0x1d, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03), id_ce_inhibitAnyPolicy, "inhibitAnyPolicy"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x00, 0x00, 0x09), id_sha256, "sha256"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x00, 0x00, 0x09), id_sha384, "sha384"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x00, 0x00, 0x09), id_sha512, "sha512"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x00, 0x00, 0x09), id_sha224, "sha224"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x00, 0x00, 0x09), id_sha512_224, "sha512_224"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x00, 0x00, 0x09), id_sha512_256, "sha512_256"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x00, 0x00, 0x09), id_sha3_224, "sha3_224"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x00, 0x00, 0x09), id_sha3_256, "sha3_256"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x00, 0x00, 0x09), id_sha3_384, "sha3_384"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x00, 0x00, 0x09), id_sha3_512, "sha3_512"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b, 0x00, 0x00, 0x09), id_shake_128, "shake_128"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x09), id_shake_256, "shake_256"},
            OidInfo{make_bytes(0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01, 0x00, 0x00, 0x09), id_netscape_certExt, "netscape_certExt"},
    };

    bool OidLessThan(const OidInfo &p1, const OidInfo &p2)
    {
        return p1.encodedOid < p2.encodedOid;
    }

    bool OidEquals(OidInfo &p1, OidInfo &p2)
    {
        return std::equal(p1.encodedOid.begin(), p1.encodedOid.end(), p2.encodedOid.begin());
    }

} // local namespace

bool GetOidInfoIndex(std::span<const std::byte>& value, size_t &index)
{
    OidInfo oiTest;

    // If it is larger than our buffer, we certainly won't find it
    if (value.size() >= oiTest.encodedOid.size())
        return false;

    value = oiTest.encodedOid;
    oiTest.encodedOid[sizeof(oiTest.encodedOid) - 1] = static_cast<std::byte>(value.size());

    auto pRet = std::lower_bound(oidTable.begin(), oidTable.end(), oiTest, OidLessThan);
    // The return will be either the exact match, or will be one greater, so need to check
    // Can also be not found
    if (pRet == oidTable.end() || !OidEquals(*pRet, oiTest))
        return false;

    index = static_cast<size_t>(pRet - oidTable.begin());
    return true;
}

std::string GetOidString(size_t index)
{
    if (index >= oidTable.size())
        return "";

    return oidTable[index].oid;
}

std::string GetOidLabel(size_t index)
{
    if (index >= oidTable.size())
        return "";

    return oidTable[index].szOidLabel;
}

ExtensionId OidToExtensionId(const char * szOidTag)
{
    // Note - these are ranked in order of which are most common
    if (szOidTag == id_ce_keyUsage)
        return ExtensionId::KeyUsage;

    if (szOidTag == id_ce_extKeyUsage)
        return ExtensionId::ExtendedKeyUsage;

    if (szOidTag == id_ce_subjectKeyIdentifier)
        return ExtensionId::SubjectKeyIdentifier;

    if (szOidTag == id_ce_authorityKeyIdentifier)
        return ExtensionId::AuthorityKeyIdentifier;

    if (szOidTag == id_ce_cRLDistributionPoints)
        return ExtensionId::CRLDistributionPoints;

    if (szOidTag == id_pe_authorityInfoAccess)
        return ExtensionId::AuthorityInfoAccess;

    if (szOidTag == id_ce_subjectAltName)
        return ExtensionId::SubjectAltName;

    if (szOidTag == id_microsoft_appCertPolicies)
        return ExtensionId::MicrosoftAppCertPolicies;

    if (szOidTag == id_ce_certificatePolicies)
        return ExtensionId::CertificatePolicies;

    if (szOidTag == id_microsoft_certTemplate)
        return ExtensionId::MicrosoftCertTemplate;

    if (szOidTag == id_ce_authorityKeyIdentifier_old)
        return ExtensionId::AuthorityKeyIdentifierOld;

    if (szOidTag == id_ce_basicConstraints)
        return ExtensionId::BasicConstraints;

    if (szOidTag == id_google_certTransparancy)
        return ExtensionId::GoogleCertTransparancy;

    if (szOidTag == id_smimeCapabilities)
        return ExtensionId::SMIMECapabilities;

    if (szOidTag == id_microsoft_certsrvCAVersion)
        return ExtensionId::MicrosoftCertSrvCAVersion;

    if (szOidTag == id_microsoft_enrollCertType)
        return ExtensionId::MicrosoftEnrollCertType;

    if (szOidTag == id_microsoft_certFriendlyName)
        return ExtensionId::MicrosoftCertFriendlyName;

    if (szOidTag == id_microsoft_certsrvPrevHash)
        return ExtensionId::MicrosoftCertSrvPrevHash;

    if (szOidTag == id_apple_pushDev)
        return ExtensionId::ApplePushDev;

    if (szOidTag == id_apple_pushProd)
        return ExtensionId::ApplePushProd;

    if (szOidTag == id_apple_custom6)
        return ExtensionId::AppleCustom6;

    if (szOidTag == id_entrustVersInfo)
        return ExtensionId::EntrustVersionInfo;

    if (szOidTag == id_ce_issuerAltName)
        return ExtensionId::IssuerAltName;

    if (szOidTag == id_netscape_certExt)
        return ExtensionId::NetscapeCertExt;

    if (szOidTag == id_ce_privateKeyUsagePeriod)
        return ExtensionId::PrivateKeyUsagePeriod;

    if (szOidTag == id_ce_keyUsageRestriction)
        return ExtensionId::KeyUsageRestriction;

    if (szOidTag == id_ce_freshestCRL)
        return ExtensionId::FreshestCRL;

    return ExtensionId::Unknown;
}

#if _DEBUG
std::string testOids[] =
    {
        "0.9.2342.19200300.100.1.1",
        "0.9.2342.19200300.100.1.25",
        "1.2.840.113533.7.65.0",
        "1.2.840.113549.1.1.1",
        "1.2.840.113549.1.1.10",
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
        "1.2.840.113549.1.1.4",
        "1.2.840.113549.1.1.5",
        "1.2.840.113549.1.1.8",
        "1.2.840.113549.1.9.1",
        "1.2.840.113549.1.9.15",
        "1.2.840.113635.100.6.3.1",
        "1.2.840.113635.100.6.3.2",
        "1.2.840.113635.100.6.3.6",
        "1.3.14.3.2.29",
        "1.3.6.1.4.1.11129.2.4.2",
        "1.3.6.1.4.1.311.20.2",
        "1.3.6.1.4.1.311.21.1",
        "1.3.6.1.4.1.311.21.10",
        "1.3.6.1.4.1.311.21.2",
        "1.3.6.1.4.1.311.21.7",
        "1.3.6.1.4.1.311.60.2.1.3",
        "1.3.6.1.5.5.7.1.1",
        "2.16.840.1.101.3.4.2.1",
        "2.16.840.1.113730.1.1",
        "2.5.29.1",
        "2.5.29.14",
        "2.5.29.15",
        "2.5.29.16",
        "2.5.29.17",
        "2.5.29.18",
        "2.5.29.19",
        "2.5.29.31",
        "2.5.29.32",
        "2.5.29.35",
        "2.5.29.37",
        "2.5.29.4",
        "2.5.29.46",
        "2.5.4.10",
        "2.5.4.11",
        "2.5.4.15",
        "2.5.4.17",
        "2.5.4.3",
        "2.5.4.5",
        "2.5.4.6",
        "2.5.4.7",
        "2.5.4.8",
        "2.5.4.9"};

void CheckOids()
{
    for (int32_t i = 0; i < _countof(testOids); ++i)
    {
        ObjectIdentifier oi;

        oi.SetValue(testOids[i]);
        auto sz = oi.GetOidLabel();
        // if (sz == "")
        //     std::cout << "Oid not found: " << testOids[i] << std::endl;
    }
}

void TestOidTable()
{
    // Ensure that they are ordered correctly
    for (size_t i = 1; i < oidTable.size(); ++i)
    {
        const OidInfo &o1 = oidTable[i - 1];
        const OidInfo &o2 = oidTable[i];

        if (!OidLessThan(o1, o2))
            throw std::runtime_error("Incorrect table ordering");
    }

    for (auto &oid: oidTable)
    {
        // Now make sure that everything is going to round-trip, and the lower bound works
        ObjectIdentifier oi;

        oi.SetValue(oid.oid);
        auto sz = oi.GetOidString();
        if (sz.empty() || sz != oid.oid)
            throw std::runtime_error("Oid String decode error");

        // Flush out any entries without tags
        if (oid.szOidLabel.empty())
            std::cout << "Missing label: " << oid.oid << std::endl;
    }

    CheckOids();
}

#else
void TestOidTable()
{
}
void CheckOids() {}
#endif