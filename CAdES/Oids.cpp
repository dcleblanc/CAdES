// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Common.h"

#define REGENERATE_TABLE
#ifdef REGENERATE_TABLE

struct OidAndPtr
{
    const char* oid;
    const char* varname;
};

OidAndPtr knownOids[] =
{
    {id_at, "id_at"},
    {id_at_surname, "id_at_surname"},
    {id_at_name, "id_at_name"},
    {id_at_givenName, "id_at_givenName"},
    {id_at_initials, "id_at_initials"},
    {id_at_generationQualifier, "id_at_generationQualifier"},
    { id_at_commonName, "id_at_commonName" },
    { id_at_serialNumber, "id_at_serialNumber" },
    { id_at_countryName, "id_at_countryName" },
    { id_at_localityName, "id_at_localityName" },
    { id_at_stateOrProvinceName, "id_at_stateOrProvinceName" },
    { id_at_streetAddress, "id_at_streetAddress" },
    { id_at_organizationName, "id_at_organizationName" },
    { id_at_organizationUnitName, "id_at_organizationUnitName" },
    { id_at_title, "id_at_title" },
    { id_at_distinguishedName, "id_at_distinguishedName" },
    { id_at_pseudonym, "id_at_pseudonym" },
    {id_ce, "id_ce"},
    {id_ce_subjectDirectoryAttributes, "id_ce_subjectDirectoryAttributes"},
    {id_ce_subjectKeyIdentifier, "id_ce_subjectKeyIdentifier"},
    {id_ce_keyUsage, "id_ce_keyUsage"},
    {id_ce_privateKeyUsagePeriod, "id_ce_privateKeyUsagePeriod"},
    {id_ce_subjectAltName, "id_ce_subjectAltName"},
    {id_ce_issuerAltName, "id_ce_issuerAltName"},
    {id_ce_basicConstraints, "id_ce_basicConstraints"},
    {id_ce_cRLNumber, "id_ce_cRLNumber"},
    {id_ce_cRLReasons, "id_ce_cRLReasons"},
    {id_ce_holdInstructionCode, "id_ce_holdInstructionCode"},
    {id_ce_invalidityDate, "id_ce_invalidityDate"},
    {id_ce_deltaCRLIndicator, "id_ce_deltaCRLIndicator"},
    {id_ce_issuingDistributionPoint, "id_ce_issuingDistributionPoint"},
    {id_ce_certificateIssuer, "id_ce_certificateIssuer"},
    {id_ce_nameConstraints, "id_ce_nameConstraints"},
    {id_ce_cRLDistributionPoints, "id_ce_cRLDistributionPoints"},
    {id_ce_certificatePolicies, "id_ce_certificatePolicies"},
    {id_ce_certificatePolicies_anyPolicy, "id_ce_certificatePolicies_anyPolicy"},
    {id_ce_policyMappings, "id_ce_policyMappings"},
    {id_ce_authorityKeyIdentifier_old, "id_ce_authorityKeyIdentifier_old"},
    {id_ce_policyConstraints, "id_ce_policyConstraints"},
    {id_ce_extKeyUsage, "id_ce_extKeyUsage"},
    {id_ce_extKeyUsage_any, "id_ce_extKeyUsage_any"},
    {id_ce_freshestCRL, "id_ce_freshestCRL"},
    {id_ce_inhibitAnyPolicy, "id_ce_inhibitAnyPolicy"},
    {id_holdInstruction, "id_holdInstruction"},
    {id_holdInstruction_none, "id_holdInstruction_none"},
    {id_holdInstruction_callissuer, "id_holdInstruction_callissuer"},
    {id_holdInstruction_reject, "id_holdInstruction_reject"},
    {id_pkix, "id_pkix"},
    {id_pe, "id_pe"},
    {id_qt, "id_qt"},
    {id_kp, "id_kp"},
    {id_ad, "id_ad"},
    {id_pe_authorityInfoAccess, "id_pe_authorityInfoAccess"},
    {id_pe_subjectInfoAccess, "id_pe_subjectInfoAccess"},
    {id_qt_cps, "id_qt_cps"},
    {id_qt_unotice, "id_qt_unotice"},
    {id_kp_serverAuth, "id_kp_serverAuth"},
    {id_kp_clientAuth, "id_kp_clientAuth"},
    {id_kp_codeSigning, "id_kp_codeSigning"},
    {id_kp_emailProtection, "id_kp_emailProtection"},
    {id_kp_timeStamping, "id_kp_timeStamping"},
    {id_kp_OCSPSigning, "id_kp_OCSPSigning"},
    {id_ad_ocsp, "id_ad_ocsp"},
    {id_ad_caIssuers, "id_ad_caIssuers"},
    {id_ad_timeStamping, "id_ad_timeStamping"},
    {id_ad_caRepository, "id_ad_caRepository"},
    {pkcs_9, "pkcs_9"},
    {id_emailAddress, "id_emailAddress"},
    {id_data, "id_data"},
    {id_signedData, "id_signedData"},
    {id_contentType, "id_contentType"},
    {id_messageDigest, "id_messageDigest"},
    {id_signingTime, "id_signingTime"},
    {id_countersignature, "id_countersignature"},
    {id_aa_signingCertificate, "id_aa_signingCertificate"},
    {id_aa_signingCertificateV2, "id_aa_signingCertificateV2"},
    {id_md2, "id_md2"},
    {id_md5, "id_md5"},
    {id_sha1, "id_sha1"},
    {id_sha256, "id_sha256"},
    {id_sha384, "id_sha384"},
    {id_sha512, "id_sha512"},
    {id_sha224, "id_sha224"},
    {id_sha512_224, "id_sha512_224"},
    {id_sha512_256, "id_sha512_256"},
    {id_sha3_224, "id_sha3_224"},
    {id_sha3_256, "id_sha3_256"},
    {id_sha3_384, "id_sha3_384"},
    {id_sha3_512, "id_sha3_512"},
    {id_shake_128, "id_shake_128"},
    {id_shake_256, "id_shake_256"},
    {id_pkcs_1, "id_pkcs_1"},
    {id_rsaEncryption, "id_rsaEncryption"},
    {id_md2WithRSAEncryption, "id_md2WithRSAEncryption"},
    {id_md5WithRSAEncryption, "id_md5WithRSAEncryption"},
    {id_sha1WithRSAEncryption, "id_sha1WithRSAEncryption"},
    {id_sha256WithRSAEncryption, "id_sha256WithRSAEncryption"},
    {id_sha384WithRSAEncryption, "id_sha384WithRSAEncryption"},
    {id_sha512WithRSAEncryption, "id_sha512WithRSAEncryption"},
    {id_sha224WithRSAEncryption, "id_sha224WithRSAEncryption"},
    {id_dsa_with_sha1, "id_dsa_with_sha1"},
    {ansi_X9_62, "ansi_X9_62"},
    {id_ecSigType, "id_ecSigType"},
    {id_ecdsa_with_SHA1, "id_ecdsa_with_SHA1"},
    {id_ecdsa_with_SHA224, "id_ecdsa_with_SHA224"},
    {id_ecdsa_with_SHA256, "id_ecdsa_with_SHA256"},
    {id_ecdsa_with_SHA384, "id_ecdsa_with_SHA384"},
    {id_ecdsa_with_SHA512, "id_ecdsa_with_SHA512" },
    { id_pilot_userid, "id_pilot_userid" },
    { id_pilot_domainComponent, "id_pilot_domainComponent" },
    { id_entrustVersInfo, "id_entrustVersInfo" },
    { id_cti_ets_proofOfOrigin, "id_cti_ets_proofOfOrigin" },
    { id_cti_ets_proofOfReceipt, "id_cti_ets_proofOfReceipt" },
    { id_cti_ets_proofOfDelivery, "id_cti_ets_proofOfDelivery" },
    { id_cti_ets_proofOfSender, "id_cti_ets_proofOfSender" },
    { id_cti_ets_proofOfApproval, "id_cti_ets_proofOfApproval" },
    { id_cti_ets_proofOfCreation, "id_cti_ets_proofOfCreation" },
    { id_smimeCapabilities, "id_smimeCapabilities" },
    { id_mgf1, "id_mgf1" },
    { rsassa_pss, "rsassa_pss" },
    { id_apple_pushDev, "id_apple_pushDev" },
    { id_apple_pushProd, "id_apple_pushProd" },
    { id_apple_custom6, "id_apple_custom6" },
    { id_sha1WithRSASignature, "id_sha1WithRSASignature" },
    { id_google_certTransparancy, "id_google_certTransparancy" },
    { id_microsoft_enrollCertType, "id_microsoft_enrollCertType" },
    { id_microsoft_certsrvCAVersion, "id_microsoft_certsrvCAVersion" },
    { id_microsoft_jurisdictionOfIncorporationCountryName, "id_microsoft_jurisdictionOfIncorporationCountryName" },
    { id_netscape_certExt, "id_netscape_certExt" },
    { id_ce_authorityKeyIdentifier, "id_ce_authorityKeyIdentifier" },
    { id_ce_keyUsageRestriction, "id_ce_keyUsageRestriction" },
    { id_at_businessCategory, "id_at_businessCategory" },
    { id_at_postalCode, "id_at_postalCode" },
    { id_microsoft_appCertPolicies, "id_microsoft_appCertPolicies" },
    { id_microsoft_certsrvPrevHash, "id_microsoft_certsrvPrevHash" },
    { id_microsoft_certTemplate, "id_microsoft_certTemplate" },
};


class OidHelper
{
public:
    const char* oid;
    const unsigned char* encodedOid; // ASN.1 encoding
    const char* textOid; // Friendly name
    const char* varName;
};

#include <map>
#include <stdio.h>
void PrintOids()
{
    // This is all terribly inefficient, but is only used
    // to create the structure definition we need
    typedef std::vector<unsigned char> oidBytes;
    std::map<oidBytes, OidHelper> oidMap;
    size_t maxKeylen = 0;
    unsigned char keybuf[12];

    for (size_t i = 0; i < _countof(knownOids); ++i)
    {
        ObjectIdentifier oi;
        oi.SetValue(knownOids[i].oid);

        oidBytes key = oi.GetBytes();
        OidHelper hlp;

        if (key.size() > maxKeylen)
            maxKeylen = key.size();

        hlp.oid = knownOids[i].oid;
        hlp.textOid = nullptr;
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
        const oidBytes& key = (*it).first;
        const OidHelper& oh = (*it).second;

        memset(keybuf, 0, sizeof(keybuf));
        memcpy_s(keybuf, sizeof(keybuf), &key[0], key.size());
        keybuf[sizeof(keybuf) - 1] = static_cast<unsigned char>(key.size());

        printf("\t{ { 0x%02x, ", (unsigned char)keybuf[0]);
        for (int i = 1; i < sizeof(keybuf) - 1; ++i)
        {
            printf("0x%02x, ", (unsigned char)keybuf[i]);
        }
        printf("0x%02x }, ", (unsigned char)keybuf[sizeof(keybuf) - 1]);
        printf("%s, ", oh.varName);
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
        unsigned char encodedOid[12];
        const char* szOid;
        const char* szOidLabel;
    };

    // Note - last byte is the number of octets used
    // This disambiguates 1.2.3.4 and 1.2.3.4.0
    OidInfo oidTable[] =
    {
        { { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01, 0x00, 0x0a }, id_pilot_userid, "pilot_userid" },                                              
        { { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x00, 0x0a }, id_pilot_domainComponent, "pilot_domainComponent" },                            
        { { 0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x41, 0x00, 0x00, 0x00, 0x09 }, id_entrustVersInfo, "entrustVersInfo" },                                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_pkcs_1, "PKCS1" },                                                           
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x00, 0x00, 0x09 }, id_rsaEncryption, "RSA Encryption" },                                           
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02, 0x00, 0x00, 0x09 }, id_md2WithRSAEncryption, "md2WithRSAEncryption" },                              
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x00, 0x00, 0x09 }, id_md5WithRSAEncryption, "md5WithRSAEncryption" },                              
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x00, 0x00, 0x09 }, id_sha1WithRSASignature, "id_sha1WithRSASignature" },                           
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x00, 0x00, 0x09 }, id_mgf1, "mgf1" },                                                              
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x00, 0x00, 0x09 }, rsassa_pss, "rsassa_pss" },                                                     
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x00, 0x00, 0x09 }, id_sha256WithRSAEncryption, "sha256WithRSAEncryption" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x00, 0x00, 0x09 }, id_sha384WithRSAEncryption, "sha384WithRSAEncryption" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x00, 0x00, 0x09 }, id_sha512WithRSAEncryption, "sha512WithRSAEncryption" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e, 0x00, 0x00, 0x09 }, id_sha224WithRSAEncryption, "sha224WithRSAEncryption" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x00, 0x00, 0x09 }, id_data, "data" },                                                              
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0x00, 0x00, 0x09 }, id_signedData, "signedData" },                                                  
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x00, 0x00, 0x00, 0x08 }, pkcs_9, "PKCS9" },                                                              
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x00, 0x00, 0x09 }, id_emailAddress, "emailAddress" }, // Deprecated, use altName extension         
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03, 0x00, 0x00, 0x09 }, id_contentType, "contentType" },                                                
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x00, 0x00, 0x09 }, id_messageDigest, "messageDigest" },                                            
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05, 0x00, 0x00, 0x09 }, id_signingTime, "signingTime" },                                                
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06, 0x00, 0x00, 0x09 }, id_countersignature, "countersignature" },                                      
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f, 0x00, 0x00, 0x09 }, id_smimeCapabilities, "smimeCapabilities" },                                    
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x00, 0x0a }, id_cti_ets_proofOfOrigin, "cti_ets_proofOfOrigin" },                            
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x00, 0x0a }, id_cti_ets_proofOfReceipt, "cti_ets_proofOfReceipt" },                          
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c, 0x0b }, id_aa_signingCertificate, "signingCertificate" },                               
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f, 0x0b }, id_aa_signingCertificateV2, "signingCertificateV2" },                           
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x00, 0x0a }, id_cti_ets_proofOfDelivery, "cti_ets_proofOfDelivery" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x04, 0x00, 0x0a }, id_cti_ets_proofOfSender, "cti_ets_proofOfSender" },                            
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x05, 0x00, 0x0a }, id_cti_ets_proofOfApproval, "cti_ets_proofOfApproval" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x06, 0x00, 0x0a }, id_cti_ets_proofOfCreation, "cti_ets_proofOfCreation" },                        
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x00, 0x00, 0x00, 0x08 }, id_md2, "md2" },
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x00, 0x00, 0x00, 0x08 }, id_md5, "md5" },
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x01, 0x00, 0x0a }, id_apple_pushDev, "apple_pushDev" },
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x02, 0x00, 0x0a }, id_apple_pushProd, "apple_pushProd" },
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x03, 0x06, 0x00, 0x0a }, id_apple_custom6, "apple_custom6" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 }, id_holdInstruction, "holdInstruction" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_holdInstruction_none, "holdInstruction_none" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_holdInstruction_callissuer, "holdInstruction_callissuer" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_holdInstruction_reject, "holdInstruction_reject" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_dsa_with_sha1, "dsa_with_sha1" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }, ansi_X9_62, "ECDSA" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 }, id_ecSigType, "ECDSA_signature" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_ecdsa_with_SHA1, "ecdsa_with_SHA1" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_ecdsa_with_SHA224, "ecdsa_with_SHA224" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08 }, id_ecdsa_with_SHA256, "ecdsa_with_SHA256" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x00, 0x00, 0x00, 0x08 }, id_ecdsa_with_SHA384, "ecdsa_with_SHA384" },
        { { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04, 0x00, 0x00, 0x00, 0x08 }, id_ecdsa_with_SHA512, "ecdsa_with_SHA512" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x00, 0x00, 0x09 }, id_microsoft_enrollCertType, "microsoft_enrollCertType" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01, 0x00, 0x00, 0x09 }, id_microsoft_certsrvCAVersion, "microsoft_certsrvCAVersion" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x02, 0x00, 0x00, 0x09 }, id_microsoft_certsrvPrevHash, "id_microsoft_certsrvPrevHash" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07, 0x00, 0x00, 0x09 }, id_microsoft_certTemplate, "id_microsoft_certTemplate" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0a, 0x00, 0x00, 0x09 }, id_microsoft_appCertPolicies, "id_microsoft_appCertPolicies" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3c, 0x02, 0x01, 0x03, 0x0b }, id_microsoft_jurisdictionOfIncorporationCountryName, "microsoft_jurisdictionOfIncorporationCountryName" },
        { { 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02, 0x00, 0x0a }, id_google_certTransparancy, "google_certTransparancy" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 }, id_pkix, "PKIX" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_pe, "Private extensions" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_pe_authorityInfoAccess, "authorityInfoAccess" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x08 }, id_pe_subjectInfoAccess, "subjectInfoAccess" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_qt, "qt" }, // (PKIX) policy qualifier types 
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_qt_cps, "qt_cps" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x00, 0x00, 0x00, 0x08 }, id_qt_unotice, "unotice" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_kp, "kp" }, // Extended Key Purposes
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_kp_serverAuth, "serverAuth" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08 }, id_kp_clientAuth, "clientAuth" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03, 0x00, 0x00, 0x00, 0x08 }, id_kp_codeSigning, "codeSigning" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x00, 0x00, 0x00, 0x08 }, id_kp_emailProtection, "emailProtection" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08, 0x00, 0x00, 0x00, 0x08 }, id_kp_timeStamping, "timeStamping" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x00, 0x00, 0x00, 0x08 }, id_kp_OCSPSigning, "OCSPSigning" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x00, 0x00, 0x00, 0x00, 0x07 }, id_ad, "ad" }, // Access descriptors 
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x00, 0x00, 0x00, 0x08 }, id_ad_ocsp, "ocsp" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x00, 0x00, 0x00, 0x08 }, id_ad_caIssuers, "caIssuers" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x03, 0x00, 0x00, 0x00, 0x08 }, id_ad_timeStamping, "timeStamping" },
        { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05, 0x00, 0x00, 0x00, 0x08 }, id_ad_caRepository, "caRepository" },
        { { 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }, id_sha1, "sha1" },
        { { 0x2b, 0x0e, 0x03, 0x02, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }, id_sha1WithRSAEncryption, "sha1WithRSAEncryption" },
        { { 0x55, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }, id_at, "at" }, // Attribute types
        { { 0x55, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_commonName, "commonName" },
        { { 0x55, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_surname, "surname" },
        { { 0x55, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_serialNumber, "serialNumber" },
        { { 0x55, 0x04, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_countryName, "countryName" },
        { { 0x55, 0x04, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_localityName, "localityName" },
        { { 0x55, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_stateOrProvinceName, "stateOrProvinceName" },
        { { 0x55, 0x04, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_streetAddress, "streetAddress" },
        { { 0x55, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_organizationName, "organizationName" },
        { { 0x55, 0x04, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_organizationUnitName, "organizationUnitName" },
        { { 0x55, 0x04, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_title, "title" },
        { { 0x55, 0x04, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_businessCategory, "businessCategory" },
        { { 0x55, 0x04, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_postalCode, "postalCode" },
        { { 0x55, 0x04, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_name, "name" },
        { { 0x55, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_givenName, "givenName" },
        { { 0x55, 0x04, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_initials, "initials" },
        { { 0x55, 0x04, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_generationQualifier, "generationQualifier" },
        { { 0x55, 0x04, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_distinguishedName, "distinguishedName" },
        { { 0x55, 0x04, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_at_pseudonym, "pseudonym" },
        { { 0x55, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }, id_ce, "ce" }, // Certificate extension
        { { 0x55, 0x1d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_authorityKeyIdentifier_old, "authorityKeyIdentifier_old" },
        { { 0x55, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_keyUsageRestriction, "keyUsageRestriction" },
        { { 0x55, 0x1d, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_subjectDirectoryAttributes, "subjectDirectoryAttributes" },
        { { 0x55, 0x1d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_subjectKeyIdentifier, "subjectKeyIdentifier" },
        { { 0x55, 0x1d, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_keyUsage, "keyUsage" },
        { { 0x55, 0x1d, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_privateKeyUsagePeriod, "privateKeyUsagePeriod" },
        { { 0x55, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_subjectAltName, "subjectAltName" },
        { { 0x55, 0x1d, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_issuerAltName, "issuerAltName" },
        { { 0x55, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_basicConstraints, "basicConstraints" },
        { { 0x55, 0x1d, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_cRLNumber, "cRLNumber" },
        { { 0x55, 0x1d, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_cRLReasons, "cRLReasons" },
        { { 0x55, 0x1d, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_holdInstructionCode, "holdInstructionCode" },
        { { 0x55, 0x1d, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_invalidityDate, "invalidityDate" },
        { { 0x55, 0x1d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_deltaCRLIndicator, "deltaCRLIndicator" },
        { { 0x55, 0x1d, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_issuingDistributionPoint, "issuingDistributionPoint" },
        { { 0x55, 0x1d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_certificateIssuer, "certificateIssuer" },
        { { 0x55, 0x1d, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_nameConstraints, "nameConstraints" },
        { { 0x55, 0x1d, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_cRLDistributionPoints, "cRLDistributionPoints" },
        { { 0x55, 0x1d, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_certificatePolicies, "certificatePolicies" },
        { { 0x55, 0x1d, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 }, id_ce_certificatePolicies_anyPolicy, "certificatePolicies_anyPolicy" },
        { { 0x55, 0x1d, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_policyMappings, "policyMappings" },
        { { 0x55, 0x1d, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_authorityKeyIdentifier, "authorityKeyIdentifier" },
        { { 0x55, 0x1d, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_policyConstraints, "policyConstraints" },
        { { 0x55, 0x1d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_extKeyUsage, "extKeyUsage" },
        { { 0x55, 0x1d, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 }, id_ce_extKeyUsage_any, "extKeyUsage_any" },
        { { 0x55, 0x1d, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_freshestCRL, "freshestCRL" },
        { { 0x55, 0x1d, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 }, id_ce_inhibitAnyPolicy, "inhibitAnyPolicy" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x00, 0x00, 0x09 }, id_sha256, "sha256" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x00, 0x00, 0x09 }, id_sha384, "sha384" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x00, 0x00, 0x09 }, id_sha512, "sha512" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x00, 0x00, 0x09 }, id_sha224, "sha224" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x00, 0x00, 0x09 }, id_sha512_224, "sha512_224" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x00, 0x00, 0x09 }, id_sha512_256, "sha512_256" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x00, 0x00, 0x09 }, id_sha3_224, "sha3_224" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x00, 0x00, 0x09 }, id_sha3_256, "sha3_256" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x00, 0x00, 0x09 }, id_sha3_384, "sha3_384" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x00, 0x00, 0x09 }, id_sha3_512, "sha3_512" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b, 0x00, 0x00, 0x09 }, id_shake_128, "shake_128" },
        { { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c, 0x00, 0x00, 0x09 }, id_shake_256, "shake_256" },
        { { 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01, 0x00, 0x00, 0x09 }, id_netscape_certExt, "netscape_certExt" },
    };

    bool OidLessThan(const OidInfo& p1, const OidInfo& p2)
    {
        int ret = memcmp(p1.encodedOid, p2.encodedOid, sizeof(p1.encodedOid));
        
        if (ret < 0)
            return true;

        return false;
    }

    bool OidEquals(OidInfo& p1, OidInfo& p2)
    {
        int ret = memcmp(p1.encodedOid, p2.encodedOid, sizeof(p1.encodedOid));

        if (ret == 0)
            return true;

        return false;
    }

} // local namespace

bool GetOidInfoIndex(const std::vector<unsigned char>& value, size_t& index)
{
    OidInfo* pRet = nullptr;
    OidInfo* pLast = oidTable + _countof(oidTable);
    OidInfo oiTest = { 0 };

    if (value.size() >= sizeof(oiTest.encodedOid))
        throw std::exception("Insufficient buffer");

    memcpy_s(oiTest.encodedOid, sizeof(oiTest.encodedOid), &value[0], value.size());
    oiTest.encodedOid[sizeof(oiTest.encodedOid) - 1] = static_cast<unsigned char>(value.size());

    pRet = std::lower_bound(oidTable, oidTable + _countof(oidTable), oiTest, OidLessThan);
    // The return will be either the exact match, or will be one greater, so need to check
    // Can also be not found
    if (pRet == pLast || !OidEquals(*pRet, oiTest))
        return false;

    index = static_cast<size_t>(pRet - oidTable);
    return true;
}

const char* GetOidString(size_t index)
{
    if (index >= _countof(oidTable))
        return nullptr;

    return oidTable[index].szOid;
}

const char* GetOidLabel(size_t index)
{
    if (index >= _countof(oidTable))
        return nullptr;

    return oidTable[index].szOidLabel;
}

ExtensionId OidToExtensionId(const char* szOidTag)
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
const char* testOids[] =
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
    "2.5.4.9"
};

void CheckOids()
{
    for (int i = 0; i < _countof(testOids); ++i)
    {
        ObjectIdentifier oi;

        oi.SetValue(testOids[i]);
        const char* sz = oi.GetOidLabel();
        if (sz == nullptr)
            std::cout << "Oid not found: " << testOids[i] << std::endl;
    }
}

void TestOidTable()
{
    // Ensure that they are ordered correctly
    for (size_t i = 1; i < _countof(oidTable); ++i)
    {
        const OidInfo& o1 = oidTable[i - 1];
        const OidInfo& o2 = oidTable[i];

        if (!OidLessThan(o1, o2))
            throw std::runtime_error("Incorrect table ordering");
    }

    for (size_t i = 1; i < _countof(oidTable); ++i)
    {
        // Now make sure that everything is going to round-trip, and the lower bound works
        ObjectIdentifier oi;

        oi.SetValue(oidTable[i].szOid);
        const char* sz = oi.GetOidString();
        if (sz == nullptr || strcmp(sz, oidTable[i].szOid) != 0)
            throw std::runtime_error("Oid String decode error");

        // Flush out any entries without tags
        if (*oidTable[i].szOidLabel == '\0')
            std::cout << "Missing label: " << oidTable[i].szOid << std::endl;
    }

    CheckOids();
}

#else
    void TestOidTable(){}
    void CheckOids(){}
#endif