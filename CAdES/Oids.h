// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

// Attributes from https://www.ietf.org/rfc/rfc5280.txt

/*
-- Arc for standard naming attributes

id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
*/
const char id_at[] = "2.5.4";

const char id_at_surname[]             = "2.5.4.4";
const char id_at_name[]                = "2.5.4.41";
const char id_at_givenName[]           = "2.5.4.42";
const char id_at_initials[]            = "2.5.4.43";
const char id_at_generationQualifier[] = "2.5.4.44";

/*
Standard extensions:
id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 }
id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }

id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
*/

const char id_ce[]                               = "2.5.29";
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
{joint-iso-itu-t(2) member-body(2) us(840) x9cm(10040) 2}
*/
const char id_holdInstruction[]            = "2.2.840.10040";
const char id_holdInstruction_none[]       = "2.2.840.10040.1";
const char id_holdInstruction_callissuer[] = "2.2.840.10040.2";
const char id_holdInstruction_reject[]     = "2.2.840.10040.3";

/*
{ iso(1) identified-organization(3) dod(6) internet(1)
security(5) mechanisms(5) pkix(7) }
*/
const char id_pkix[] = "1.3.6.1.5.7";

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
const char id_pe[] = "1.3.6.1.5.7.1";
const char id_qt[] = "1.3.6.1.5.7.2";
const char id_kp[] = "1.3.6.1.5.7.3";
const char id_ad[] = "1.3.6.1.5.7.48";

const char id_pe_authorityInfoAccess[] = "1.3.6.1.5.7.1.1";
const char id_pe_subjectInfoAccess[]   = "1.3.6.1.5.7.1.11";

/*
-- policyQualifierIds for Internet policy qualifiers

id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
-- OID for CPS qualifier
id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
-- OID for user notice qualifier

PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )

*/

const char id_qt_cps[]     = "1.3.6.1.5.7.2.1";
const char id_qt_unotice[] = "1.3.6.1.5.7.2.2";

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

const char id_kp_serverAuth[]      = "1.3.6.1.5.7.3.1";
const char id_kp_clientAuth[]      = "1.3.6.1.5.7.3.2";
const char id_kp_codeSigning[]     = "1.3.6.1.5.7.3.3";
const char id_kp_emailProtection[] = "1.3.6.1.5.7.3.4";
const char id_kp_timeStamping[]    = "1.3.6.1.5.7.3.8";
const char id_kp_OCSPSigning[]     = "1.3.6.1.5.7.3.9";

/*
--access descriptor definitions

id - ad - ocsp         OBJECT IDENTIFIER :: = { id - ad 1 }
id - ad - caIssuers    OBJECT IDENTIFIER :: = { id - ad 2 }
id - ad - timeStamping OBJECT IDENTIFIER :: = { id - ad 3 }
id - ad - caRepository OBJECT IDENTIFIER :: = { id - ad 5 }
*/

const char id_ad_ocsp[]         = "1.3.6.1.5.7.48.1";
const char id_ad_caIssuers[]    = "1.3.6.1.5.7.48.2";
const char id_ad_timeStamping[] = "1.3.6.1.5.7.48.3";
const char id_ad_caRepository[] = "1.3.6.1.5.7.48.5";

/*
Legacy 

pkcs-9 OBJECT IDENTIFIER ::=
{ iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
*/

const char pkcs_9[] = "1.2.840.113549.1.9";
const char id_emailAddress[] = "1.2.840.113549.1.9.1";

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
Algorithms
*/

// MD2, MD5, SHA1 in RFC 3279, SHA2 in RFC 4055
// Identifiers defined in https://tools.ietf.org/html/rfc4055
const char id_md2[]        = "1.2.840.113549.2.2";
const char id_md5[]        = "1.2.840.113549.2.5";
const char id_sha1[]       = "1.3.14.3.2.26";
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
const char id_sha1WithRSAEncryption[] = "1.2.840.113549.1.1.5";

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
