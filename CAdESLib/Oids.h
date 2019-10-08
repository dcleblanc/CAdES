// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// Attributes from https://www.ietf.org/rfc/rfc5280.txt

/*
    When adding any additional OIDs to this header, ensure that you also add them to
    the knownOids table in Oids.cpp, regenerate the table, and patch the oidTable so that 
    the added OIDs show up in the right place.

*/

/*
-- Arc for standard naming attributes

id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
See https://tools.ietf.org/html/rfc4519 for additional OID definitions

RFC 5280, section 4.1.2.4:
Implementations of this specification MUST
be prepared to receive the following standard attribute types in
issuer and subject (Section 4.1.2.6) names:

* country,
* organization,
* organizational unit,
* distinguished name qualifier, 
* state or province name,
* common name (e.g., "Susan Housley"), and 
* serial number. 

In addition, implementations of this specification SHOULD be prepared
to receive the following standard attribute types in issuer and
subject names:

* locality,
* title, 
* surname,
* given name,
* initials,
* pseudonym, and 
* generation qualifier (e.g., "Jr.", "3rd", or "IV").

*/
const char id_at[] = "2.5.4";

const char id_at_commonName[]           = "2.5.4.3";
const char id_at_surname[]              = "2.5.4.4";
const char id_at_serialNumber[]         = "2.5.4.5";
const char id_at_countryName[]          = "2.5.4.6";
const char id_at_localityName[]         = "2.5.4.7";
const char id_at_stateOrProvinceName[]  = "2.5.4.8";
const char id_at_streetAddress[]        = "2.5.4.9";
const char id_at_organizationName[]     = "2.5.4.10";
const char id_at_organizationUnitName[] = "2.5.4.11";
const char id_at_title[]                = "2.5.4.12";
const char id_at_businessCategory[]     = "2.5.4.15";
const char id_at_postalCode[]           = "2.5.4.17";
const char id_at_name[]                 = "2.5.4.41";
const char id_at_givenName[]            = "2.5.4.42";
const char id_at_initials[]             = "2.5.4.43";
const char id_at_generationQualifier[]  = "2.5.4.44";
const char id_at_distinguishedName[]    = "2.5.4.49";
const char id_at_pseudonym[]            = "2.5.4.65";

/*
Standard extensions:
id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
*/

const char id_ce[]                               = "2.5.29";
const char id_ce_authorityKeyIdentifier_old[]    = "2.5.29.1";
const char id_ce_keyUsageRestriction[]           = "2.5.29.4"; // https://datatracker.ietf.org/doc/html/draft-ietf-pkix-ipki-part1-01.txt
const char id_ce_subjectDirectoryAttributes[]    = "2.5.29.9";
const char id_ce_subjectKeyIdentifier[]          = "2.5.29.14";
const char id_ce_keyUsage[]                      = "2.5.29.15";
const char id_ce_privateKeyUsagePeriod[]         = "2.5.29.16";
const char id_ce_subjectAltName[]                = "2.5.29.17";
const char id_ce_issuerAltName[]                 = "2.5.29.18";
const char id_ce_basicConstraints[]              = "2.5.29.19";
const char id_ce_cRLNumber[]                     = "2.5.29.20";
const char id_ce_cRLReasons[]                    = "2.5.29.21";
const char id_ce_holdInstructionCode[]           = "2.5.29.23";
const char id_ce_invalidityDate[]                = "2.5.29.24";
const char id_ce_deltaCRLIndicator[]             = "2.5.29.27";
const char id_ce_issuingDistributionPoint[]      = "2.5.29.28";
const char id_ce_certificateIssuer[]             = "2.5.29.29";
const char id_ce_nameConstraints[]               = "2.5.29.30";
const char id_ce_cRLDistributionPoints[]         = "2.5.29.31";
const char id_ce_certificatePolicies[]           = "2.5.29.32";
const char id_ce_certificatePolicies_anyPolicy[] = "2.5.29.32.0";
const char id_ce_policyMappings[]                = "2.5.29.33";
const char id_ce_authorityKeyIdentifier[]        = "2.5.29.35";
const char id_ce_policyConstraints[]             = "2.5.29.36";
const char id_ce_extKeyUsage[]                   = "2.5.29.37";
const char id_ce_extKeyUsage_any[]               = "2.5.29.37.0"; // anyExtendedKeyUsage
const char id_ce_freshestCRL[]                   = "2.5.29.46";
const char id_ce_inhibitAnyPolicy[]              = "2.5.29.54";

/*
holdInstruction OBJECT IDENTIFIER ::=
{iso(1) member-body(2) us(840) x9-57(10040) holdinstruction(2)}

Note that the appendices of IETF RFC 2459 and RFC 5280 define the (wrong) value of 2.2.840.10040.2 for this OID.

*/
const char id_holdInstruction[]            = "1.2.840.10040.2";
const char id_holdInstruction_none[]       = "1.2.840.10040.2.1";
const char id_holdInstruction_callissuer[] = "1.2.840.10040.2.2";
const char id_holdInstruction_reject[]     = "1.2.840.10040.2.3";

/*
{ iso(1) identified-organization(3) dod(6) internet(1)
security(5) mechanisms(5) pkix(7) }
*/
const char id_pkix[] = "1.3.6.1.5.5.7";

/*
-- PKIX arcs

id-pe OBJECT IDENTIFIER ::= { id-pkix 1 }
-- arc for private certificate extensions
id-qt OBJECT IDENTIFIER ::= { id-pkix 2 }
-- arc for policy qualifier types
id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
-- arc for extended key purpose OIDS
id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
-- arc for access descriptors
*/
const char id_pe[] = "1.3.6.1.5.5.7.1";
const char id_qt[] = "1.3.6.1.5.5.7.2";
const char id_kp[] = "1.3.6.1.5.5.7.3";
const char id_ad[] = "1.3.6.1.5.5.7.48";

const char id_pe_authorityInfoAccess[] = "1.3.6.1.5.5.7.1.1";
const char id_pe_subjectInfoAccess[]   = "1.3.6.1.5.5.7.1.11";

/*
-- policyQualifierIds for Internet policy qualifiers

id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
-- OID for CPS qualifier
id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
-- OID for user notice qualifier

PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

*/

const char id_qt_cps[]     = "1.3.6.1.5.5.7.2.1";
const char id_qt_unotice[] = "1.3.6.1.5.5.7.2.2";

/*
id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
-- TLS WWW server authentication
-- Key usage bits that may be consistent: digitalSignature,
-- keyEncipherment or keyAgreement

id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
-- TLS WWW client authentication
-- Key usage bits that may be consistent: digitalSignature
-- and/or keyAgreement

id-kp-codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
-- Signing of downloadable executable code
-- Key usage bits that may be consistent: digitalSignature

id-kp-emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
-- Email protection
-- Key usage bits that may be consistent: digitalSignature,
-- nonRepudiation, and/or (keyEncipherment or keyAgreement)

id-kp-timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
-- Binding the hash of an object to a time
-- Key usage bits that may be consistent: digitalSignature
-- and/or nonRepudiation

id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
-- Signing OCSP responses
-- Key usage bits that may be consistent: digitalSignature
-- and/or nonRepudiation
*/

const char id_kp_serverAuth[]      = "1.3.6.1.5.5.7.3.1";
const char id_kp_clientAuth[]      = "1.3.6.1.5.5.7.3.2";
const char id_kp_codeSigning[]     = "1.3.6.1.5.5.7.3.3";
const char id_kp_emailProtection[] = "1.3.6.1.5.5.7.3.4";
const char id_kp_timeStamping[]    = "1.3.6.1.5.5.7.3.8";
const char id_kp_OCSPSigning[]     = "1.3.6.1.5.5.7.3.9";

/*
--access descriptor definitions

id - ad - ocsp         OBJECT IDENTIFIER :: = { id - ad 1 }
id - ad - caIssuers    OBJECT IDENTIFIER :: = { id - ad 2 }
id - ad - timeStamping OBJECT IDENTIFIER :: = { id - ad 3 }
id - ad - caRepository OBJECT IDENTIFIER :: = { id - ad 5 }
*/

const char id_ad_ocsp[]         = "1.3.6.1.5.5.7.48.1";
const char id_ad_caIssuers[]    = "1.3.6.1.5.5.7.48.2";
const char id_ad_timeStamping[] = "1.3.6.1.5.5.7.48.3";
const char id_ad_caRepository[] = "1.3.6.1.5.5.7.48.5";



// See http://tools.ietf.org/html/rfc3447.html for next two
// Rivest, Shamir and Adleman (RSA) algorithm that uses the Mask Generator Function 1 (MGF1) 
const char  id_mgf1[]                   = "1.2.840.113549.1.1.8"; // http://tools.ietf.org/html/rfc3447.html
// Rivest, Shamir, Adleman (RSA) Signature Scheme with Appendix - Probabilistic Signature Scheme (RSASSA-PSS)
const char  rsassa_pss[]                = "1.2.840.113549.1.1.10"; // http://tools.ietf.org/html/rfc3447.html

/*
Legacy 

pkcs-9 OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
*/

const char pkcs_9[]                     = "1.2.840.113549.1.9";
const char id_emailAddress[]            = "1.2.840.113549.1.9.1";
const char id_smimeCapabilities[]       = "1.2.840.113549.1.9.15"; // http://tools.ietf.org/html/rfc5751

// Committment type OIDs
const char id_cti_ets_proofOfOrigin[]   = "1.2.840.113549.1.9.16.1";
const char id_cti_ets_proofOfReceipt[]  = "1.2.840.113549.1.9.16.2";
const char id_cti_ets_proofOfDelivery[] = "1.2.840.113549.1.9.16.3";
const char id_cti_ets_proofOfSender[]   = "1.2.840.113549.1.9.16.4";
const char id_cti_ets_proofOfApproval[] = "1.2.840.113549.1.9.16.5";
const char id_cti_ets_proofOfCreation[] = "1.2.840.113549.1.9.16.6";


/*
CMS content types:

id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }

*/

const char id_data[]             = "1.2.840.113549.1.7.1"; // Implies any octet string, application specific
const char id_signedData[]       = "1.2.840.113549.1.7.2"; // SignedData object
const char id_contentType[]      = "1.2.840.113549.1.9.3"; // ContentType
const char id_messageDigest[]    = "1.2.840.113549.1.9.4"; // ContentType
const char id_signingTime[]      = "1.2.840.113549.1.9.5"; // Signing time
const char id_countersignature[] = "1.2.840.113549.1.9.6"; // Countersignatures

/*
Types needed for CAdES:
*/

const char id_aa_signingCertificate[]   = "1.2.840.113549.1.9.16.2.12";
const char id_aa_signingCertificateV2[] = "1.2.840.113549.1.9.16.2.47";

/*
    Apple custom extensions
    {iso(1) member-body(2) us(840) apple(113635) appleDataSecurity(100) appleCertificateExtensions(6)}
    Only documentation found so far on this was here https://1pdf.net/apple-inc_58fdf8adf6065d884c8bb1b3

*/

const char id_apple_pushDev[]  = "1.2.840.113635.100.6.3.1"; // Apple Push Notification service Development
const char id_apple_pushProd[] = "1.2.840.113635.100.6.3.2"; // Apple Push Notification service Production
const char id_apple_custom6[]  = "1.2.840.113635.100.6.3.6"; // Custom, undefined extension

/*
    Custom Google extensions
    {iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 11129}
*/
// This is documented here - https://tools.ietf.org/html/rfc6962#section-3.3, which is Experimental
const char id_google_certTransparancy[] = "1.3.6.1.4.1.11129.2.4.2"; // Google cert transparency

/*
    Microsoft enterprise extensions
    {iso(1) identified-organization(3) dod(6) internet(1) private(4) enterprise(1) 311
    These are documented here - https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography

	Note - there are a number of OIDs that may not be in the OID reference sites, but are in wincrypt.h
	Search for this section - 
	#define szOID_CERT_PROP_ID_PREFIX           "1.3.6.1.4.1.311.10.11."
*/

const char id_microsoft_certFriendlyName[]     = "1.3.6.1.4.1.311.10.11.11"; // CERT_FRIENDLY_NAME_PROP_ID
const char id_microsoft_enrollCertType[]       = "1.3.6.1.4.1.311.20.2"; // Microsoft szOID_ENROLL_CERTTYPE_EXTENSION
const char id_microsoft_certsrvCAVersion[]     = "1.3.6.1.4.1.311.21.1"; // Microsoft szOID_CERTSRV_CA_VERSION
const char id_microsoft_certsrvPrevHash[]      = "1.3.6.1.4.1.311.21.2"; // Microsoft szOID_CERTSRV_PREVIOUS_CERT_HASH
const char id_microsoft_certsrvnNextPublish[]  = "1.3.6.1.4.1.311.21.4"; // Microsoft szOID_CRL_NEXT_PUBLISH
const char id_microsoft_certTemplate[]         = "1.3.6.1.4.1.311.21.7"; // Microsoft szOID_CERTIFICATE_TEMPLATE
const char id_microsoft_appCertPolicies[]      = "1.3.6.1.4.1.311.21.10"; // Microsoft szOID_APPLICATION_CERT_POLICIES
const char id_microsoft_jurisdictionOfIncorporationCountryName[] = "1.3.6.1.4.1.311.60.2.1.3"; // Microsoft jurisdictionOfIncorporationCountryName

// Netscape - {joint-iso-itu-t(2) country(16) us(840) organization(1) netscape(113730) cert-ext(1) cert-type(1)}
const char id_netscape_certExt[] = "2.16.840.1.113730.1.1"; // Old Netscape extensions


/*
Algorithms
*/

// MD2, MD5, SHA1 in RFC 3279, SHA2 in RFC 4055
// Identifiers defined in https://tools.ietf.org/html/rfc4055
const char id_md2[]        = "1.2.840.113549.2.2";
const char id_md5[]        = "1.2.840.113549.2.5";
const char id_sha1[]       = "1.3.14.3.2.26";
const char id_sha1WithRSAEncryption[] = "1.3.14.3.2.29";
const char id_sha256[]     = "2.16.840.1.101.3.4.2.1";
const char id_sha384[]     = "2.16.840.1.101.3.4.2.2";
const char id_sha512[]     = "2.16.840.1.101.3.4.2.3";
const char id_sha224[]     = "2.16.840.1.101.3.4.2.4";
// Next two are odd
const char id_sha512_224[] = "2.16.840.1.101.3.4.2.5";
const char id_sha512_256[] = "2.16.840.1.101.3.4.2.6";
// SHA3, see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
const char id_sha3_224[]   = "2.16.840.1.101.3.4.2.7";
const char id_sha3_256[]   = "2.16.840.1.101.3.4.2.8";
const char id_sha3_384[]   = "2.16.840.1.101.3.4.2.9";
const char id_sha3_512[]   = "2.16.840.1.101.3.4.2.10";
const char id_shake_128[]  = "2.16.840.1.101.3.4.2.11";
const char id_shake_256[]  = "2.16.840.1.101.3.4.2.12";

/*
pkcs-1  OBJECT IDENTIFIER  ::=  { iso(1) member-body(2)
us(840) rsadsi(113549) pkcs(1) 1 }
*/

const char id_pkcs_1[] = "1.2.840.113549.1.1";

// Legacy signature algorithms, sometimes seen on root certs
const char id_rsaEncryption[]         = "1.2.840.113549.1.1.1";
const char id_md2WithRSAEncryption[]  = "1.2.840.113549.1.1.2";
const char id_md5WithRSAEncryption[]  = "1.2.840.113549.1.1.4";
const char id_sha1WithRSASignature[]  = "1.2.840.113549.1.1.5";

// SHA2-RSA algorithms
const char id_sha256WithRSAEncryption[] = "1.2.840.113549.1.1.11";
const char id_sha384WithRSAEncryption[] = "1.2.840.113549.1.1.12";
const char id_sha512WithRSAEncryption[] = "1.2.840.113549.1.1.13";
const char id_sha224WithRSAEncryption[] = "1.2.840.113549.1.1.14";

// DSA, just for completeness
const char id_dsa_with_sha1[] = "1.2.840.10040.4.3";

// Elliptic Curve
const char ansi_X9_62[]           = "1.2.840.10045";
const char id_ecSigType[]         = "1.2.840.10045.4";
const char id_ecdsa_with_SHA1[]   = "1.2.840.10045.4.1";
const char id_ecdsa_with_SHA224[] = "1.2.840.10045.4.3.1";
const char id_ecdsa_with_SHA256[] = "1.2.840.10045.4.3.2";
const char id_ecdsa_with_SHA384[] = "1.2.840.10045.4.3.3";
const char id_ecdsa_with_SHA512[] = "1.2.840.10045.4.3.4";

// Weird OIDs that should not be in certificates, but end up there anyway
// This pages explains - http://www.oidref.com/0.9
//{itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) userid(1)}
// Also see https://tools.ietf.org/html/rfc1274
/*
    userid ATTRIBUTE
    WITH ATTRIBUTE-SYNTAX
    caseIgnoreStringSyntax
    (SIZE (1 .. ub-user-identifier)) 
*/
const char id_pilot_userid[]          = "0.9.2342.19200300.100.1.1";
const char id_pilot_domainComponent[] = "0.9.2342.19200300.100.1.25";

// Nortel has this OID
// {iso(1) member-body(2) us(840) nortelnetworks(113533) entrust(7) nsn-ce(65) 0(0)}
// Entrust version extension
// See http://www.digicert.com/docs/cps/DigiCert_CPS_v301.pdf
const char id_entrustVersInfo[] = "1.2.840.113533.7.65.0";

// Helper functions
bool GetOidInfoIndex(const std::vector<unsigned char>& value, size_t& index);
const char* GetOidString(size_t index);
const char* GetOidLabel(size_t index);

// Extension map

enum class ExtensionId
{
    KeyUsage = 0,
    ExtendedKeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    CRLDistributionPoints, 
    AuthorityInfoAccess,
    SubjectAltName,
    MicrosoftAppCertPolicies,
    CertificatePolicies,
    MicrosoftCertTemplate,
    AuthorityKeyIdentifierOld,
    BasicConstraints,
    GoogleCertTransparancy,
    SMIMECapabilities,
    MicrosoftCertSrvCAVersion,
    MicrosoftEnrollCertType,
	MicrosoftCertFriendlyName,
    MicrosoftCertSrvPrevHash,
    ApplePushDev,
    ApplePushProd,
    AppleCustom6,
    EntrustVersionInfo,
    IssuerAltName,
    NetscapeCertExt,
    PrivateKeyUsagePeriod,
    KeyUsageRestriction,
    FreshestCRL,
    Unknown
};

ExtensionId OidToExtensionId(const char* szOidTag);