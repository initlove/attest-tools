/*
 * Copyright (C) 2018-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: skae-asn.h
 *      SKAE definitions.
 */

#ifndef _SKAE_ASN_H
#define _SKAE_ASN_H

#include <openssl/asn1t.h>
#include <openssl/ts.h>
#include <openssl/cms.h>

/*
 * TCGSpecVersion    ::= SEQUENCE {
 *	major                              INTEGER,
 *	minor                              INTEGER
 * }
 */
typedef struct {
	ASN1_INTEGER *major;
	ASN1_INTEGER *minor;
} TCGSPECVERSION;

ASN1_SEQUENCE(TCGSPECVERSION) = {
	ASN1_EXP(TCGSPECVERSION, major, ASN1_INTEGER, 0),
	ASN1_EXP(TCGSPECVERSION, minor, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TCGSPECVERSION)

IMPLEMENT_ASN1_FUNCTIONS(TCGSPECVERSION);

/*
 * TPMCertifyInfo ::= SEQUENCE {
 *	tpmCertifyInfo                BIT STRING,
 *	signature                     BIT STRING
 * }
 */
typedef struct {
	ASN1_OCTET_STRING *tpmCertifyInfo;
	ASN1_OCTET_STRING *signature;
} TPMCERTIFYINFO;

ASN1_SEQUENCE(TPMCERTIFYINFO) = {
	ASN1_EXP(TPMCERTIFYINFO, tpmCertifyInfo, ASN1_OCTET_STRING, 0),
	ASN1_EXP(TPMCERTIFYINFO, signature, ASN1_OCTET_STRING, 1),
} ASN1_SEQUENCE_END(TPMCERTIFYINFO)

IMPLEMENT_ASN1_FUNCTIONS(TPMCERTIFYINFO);

/*
 * IssuerSerial ::= SEQUENCE {
 *	issuer                        GeneralNames,
 *	serialNumber                  CertificateSerialNumber
 * }
 */
typedef struct {
	STACK_OF(GENERAL_NAME) *GeneralNames;
	ASN1_INTEGER *CertificateSerialNumber;
} ISSUERSERIAL;

ASN1_SEQUENCE(ISSUERSERIAL) = {
	ASN1_EXP_SEQUENCE_OF(ISSUERSERIAL, GeneralNames, GENERAL_NAME, 0),
	ASN1_EXP_OPT(ISSUERSERIAL, CertificateSerialNumber, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(ISSUERSERIAL)

IMPLEMENT_ASN1_FUNCTIONS(ISSUERSERIAL)

/*
 * TPMIdentityCredentialAccessInfo  ::= SEQUENCE {
 *	authorityInfoAccess           AuthorityInfoAccessSyntax,
 *	issuerSerial                  IssuerSerial      OPTIONAL
 * }
 */
typedef struct {
	AUTHORITY_INFO_ACCESS *authorityInfoAccess;
	ISSUERSERIAL *issuerSerial;
} TPMIDENTITYCREDACCESSINFO;

ASN1_SEQUENCE(TPMIDENTITYCREDACCESSINFO) = {
	ASN1_EXP(TPMIDENTITYCREDACCESSINFO, authorityInfoAccess,
		 AUTHORITY_INFO_ACCESS, 0),
	ASN1_EXP(TPMIDENTITYCREDACCESSINFO, issuerSerial, ISSUERSERIAL, 1)
} ASN1_SEQUENCE_END(TPMIDENTITYCREDACCESSINFO)

IMPLEMENT_ASN1_FUNCTIONS(TPMIDENTITYCREDACCESSINFO);

/*
 * AttestationEvidence ::= SEQUENCE {
 *	tpmCertifyInfo                TPMCertifyInfo,
 *	tpmIdentityCredAccessInfo     TPMIdentityCredentialAccessInfo
 * }
 */
typedef struct {
	TPMCERTIFYINFO *TPMCertifyInfo;
	TPMIDENTITYCREDACCESSINFO *TPMIdentityCredentialAccessInfo;
} ATTESTATIONEVIDENCE;

ASN1_SEQUENCE(ATTESTATIONEVIDENCE) = {
	ASN1_EXP(ATTESTATIONEVIDENCE, TPMCertifyInfo, TPMCERTIFYINFO, 0),
	ASN1_EXP(ATTESTATIONEVIDENCE, TPMIdentityCredentialAccessInfo,
		 TPMIDENTITYCREDACCESSINFO, 1)
} ASN1_SEQUENCE_END(ATTESTATIONEVIDENCE)

IMPLEMENT_ASN1_FUNCTIONS(ATTESTATIONEVIDENCE);

/*
 * EncryptedAttestationInfo::= SEQUENCE {
 *	encryptionAlgorithm            AlgorithmIdentifier,
 *	encryptedAttestEvidence            OCTET      STRING
 * }
 */
typedef struct {
	X509_ALGOR *encryptionAlgorithm;
	ASN1_OCTET_STRING *encryptedAttestEvidence;
} ENCRYPTEDATTESTATIONINFO;

ASN1_SEQUENCE(ENCRYPTEDATTESTATIONINFO) = {
	ASN1_EXP(ENCRYPTEDATTESTATIONINFO, encryptionAlgorithm, X509_ALGOR, 0),
	ASN1_EXP_OPT(ENCRYPTEDATTESTATIONINFO, encryptedAttestEvidence,
		     ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(ENCRYPTEDATTESTATIONINFO)

IMPLEMENT_ASN1_FUNCTIONS(ENCRYPTEDATTESTATIONINFO);

/*
 * EnvelopedAttestationEvidence ::= SEQUENCE {
 *	recipientInfos                  RecipientInfos,
 *	encryptedAttestInfo            EncryptedAttestationInfo
 * }
 */
typedef struct {
	/* FIXME: ASN1_OCTET_STRING -> CMS_RecipientInfo */
	STACK_OF(ASN1_OCTET_STRING) *RecipientInfos;
	ENCRYPTEDATTESTATIONINFO *EncryptedAttestationInfo;
} ENVELOPEDATTESTATIONEVIDENCE;

DECLARE_ASN1_ITEM(CMS_RecipientInfo)

ASN1_SEQUENCE(ENVELOPEDATTESTATIONEVIDENCE) = {
	ASN1_EXP_SEQUENCE_OF(ENVELOPEDATTESTATIONEVIDENCE, RecipientInfos,
			     ASN1_OCTET_STRING, 0),
	ASN1_EXP(ENVELOPEDATTESTATIONEVIDENCE, EncryptedAttestationInfo,
		 ENCRYPTEDATTESTATIONINFO, 1)
} ASN1_SEQUENCE_END(ENVELOPEDATTESTATIONEVIDENCE)

IMPLEMENT_ASN1_FUNCTIONS(ENVELOPEDATTESTATIONEVIDENCE);

/*
 * KeyAttestationEvidence ::= CHOICE {
 *	attestEvidence                  [0] AttestationEvidence,
 *	envelopedAttestEvidence         [1] EnvelopedAttestationEvidence
 * }
 */
#define KEYATTESTATIONEVIDENCE_TYPE_NOT_ENVELOPED 0
#define KEYATTESTATIONEVIDENCE_TYPE_ENVELOPED 1
typedef struct {
	int type;
	union {
		ATTESTATIONEVIDENCE *attestEvidence;
		ENVELOPEDATTESTATIONEVIDENCE *EnvelopedAttestationEvidence;
	};
} KEYATTESTATIONEVIDENCE;

ASN1_CHOICE(KEYATTESTATIONEVIDENCE) = {
	ASN1_EXP(KEYATTESTATIONEVIDENCE, attestEvidence,
		 ATTESTATIONEVIDENCE, 1),
	ASN1_EXP(KEYATTESTATIONEVIDENCE, EnvelopedAttestationEvidence,
		 ENVELOPEDATTESTATIONEVIDENCE, 2)
} ASN1_CHOICE_END(KEYATTESTATIONEVIDENCE)

IMPLEMENT_ASN1_FUNCTIONS(KEYATTESTATIONEVIDENCE);

/*
 * SubjectKeyAttestationEvidence ::= SEQUENCE {
 *	tcgSpecVersion                TCGSpecVersion,
 *	keyAttestationEvidence        KeyAttestationEvidence
 * }
 */
#define OID_SKAE		"2.23.133.6.1.0"
#define OID_SKAE_DATA_URL	"2.23.133.6.1.1"

typedef struct {
	ASN1_OBJECT *type;
	TCGSPECVERSION *TCGSpecVersion;
	KEYATTESTATIONEVIDENCE *KeyAttestationEvidence;
} SUBJECTKEYATTESTATIONEVIDENCE;

ASN1_SEQUENCE(SUBJECTKEYATTESTATIONEVIDENCE) = {
	ASN1_SIMPLE(SUBJECTKEYATTESTATIONEVIDENCE, type, ASN1_OBJECT),
	ASN1_EXP(SUBJECTKEYATTESTATIONEVIDENCE, TCGSpecVersion,
		 TCGSPECVERSION, 0),
	ASN1_EXP(SUBJECTKEYATTESTATIONEVIDENCE, KeyAttestationEvidence,
		 KEYATTESTATIONEVIDENCE, 1)
} ASN1_SEQUENCE_END(SUBJECTKEYATTESTATIONEVIDENCE)

IMPLEMENT_ASN1_FUNCTIONS(SUBJECTKEYATTESTATIONEVIDENCE);

#endif /* _SKAE_ASN_H */
