#ifndef _CI_H_
#define _CI_H_

EXTERN_C_START

#ifndef ALGIDDEF
#define ALGIDDEF
typedef ULONG ALG_ID;
typedef PULONG PALG_ID;
#endif

#define ALG_CLASS_ANY                   (0)
#define ALG_CLASS_SIGNATURE             (1 << 13)
#define ALG_CLASS_MSG_ENCRYPT           (2 << 13)
#define ALG_CLASS_DATA_ENCRYPT          (3 << 13)
#define ALG_CLASS_HASH                  (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE          (5 << 13)
#define ALG_CLASS_ALL                   (7 << 13)

#define ALG_TYPE_ANY                    (0)
#define ALG_TYPE_DSS                    (1 << 9)
#define ALG_TYPE_RSA                    (2 << 9)
#define ALG_TYPE_BLOCK                  (3 << 9)
#define ALG_TYPE_STREAM                 (4 << 9)
#define ALG_TYPE_DH                     (5 << 9)
#define ALG_TYPE_SECURECHANNEL          (6 << 9)
#define ALG_TYPE_ECDH                   (7 << 9)

#define ALG_SID_MD2                     1
#define ALG_SID_MD4                     2
#define ALG_SID_MD5                     3
#define ALG_SID_SHA                     4
#define ALG_SID_SHA1                    4
#define ALG_SID_MAC                     5
#define ALG_SID_RIPEMD                  6
#define ALG_SID_RIPEMD160               7
#define ALG_SID_SSL3SHAMD5              8
#define ALG_SID_HMAC                    9
#define ALG_SID_TLS1PRF                 10
#define ALG_SID_HASH_REPLACE_OWF        11
#define ALG_SID_SHA_256                 12
#define ALG_SID_SHA_384                 13
#define ALG_SID_SHA_512                 14

#define CALG_MD2                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2)
#define CALG_MD4                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4)
#define CALG_MD5                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
#define CALG_SHA                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA)
#define CALG_SHA1               (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
#define CALG_SHA_256            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#define CALG_SHA_384            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#define CALG_SHA_512            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#define CALG_MAC                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MAC)
#define CALG_SSL3_SHAMD5        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5)
#define CALG_HMAC               (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)
#define CALG_TLS1PRF            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF)
#define CALG_HASH_REPLACE_OWF   (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF)

typedef enum _MINCRYPT_KNOWN_ROOT_ID {
    MincryptKnownRootNone = 0x0,
    MincryptKnownRootUnknown = 0x1,
    MincryptKnownRootSelfsigned = 0x2,
    MincryptKnownRootMicrosoftAuthenticodeRoot = 0x3,
    MincryptKnownRootMicrosoftProductRoot1997 = 0x4,
    MincryptKnownRootMicrosoftProductRoot2001 = 0x5,
    MincryptKnownRootMicrosoftProductRoot2010 = 0x6,
    MincryptKnownRootMicrosoftStandardRoot2011 = 0x7,
    MincryptKnownRootMicrosoftCodeVerificationRoot2006 = 0x8,
    MincryptKnownRootMicrosoftTestRoot1999 = 0x9,
    MincryptKnownRootMicrosoftTestRoot2010 = 0xA,
    MincryptKnownRootMicrosoftDMDTestRoot2005 = 0xB,
    MincryptKnownRootMicrosoftDMDRoot2005 = 0xC,
    MincryptKnownRootMicrosoftDMDPreviewRoot2005 = 0xD,
    MincryptKnownRootMicrosoftFlightRoot2014 = 0xE,
} MINCRYPT_KNOWN_ROOT_ID;

typedef struct _CRYPTOAPI_BLOB {
    ULONG cbData;
    PVOID pbData;
} CRYPTOAPI_BLOB, *PCRYPTOAPI_BLOB;

typedef struct _MINCRYPT_STRING {
    PCHAR Buffer;
    USHORT Length;
    UCHAR Asn1EncodingTag;
    UCHAR Spare[1];
} MINCRYPT_STRING, *PMINCRYPT_STRING;

typedef struct _MINCRYPT_SIGNER_INFO {
    ULONG ToBeSignedHashAlgorithm;
    ULONG ToBeSignedHashLength;
    UCHAR ToBeSignedHash[64];
    MINCRYPT_STRING PublisherCommonName;
    MINCRYPT_STRING IssuerCommonName;
    CRYPTOAPI_BLOB EncodedCertificate;
} MINCRYPT_SIGNER_INFO, *PMINCRYPT_SIGNER_INFO;

typedef struct _MINCRYPT_CHAIN_INFO {
    ULONG cbSize;
    PCRYPTOAPI_BLOB rgPublicKeys;
    ULONG cPublicKeys;
    PCRYPTOAPI_BLOB rgEKUs;
    ULONG cEKUs;
    PMINCRYPT_SIGNER_INFO rgSignerInfos;
    ULONG cSignerInfos;
    MINCRYPT_KNOWN_ROOT_ID KnownRoot;
    CRYPTOAPI_BLOB AuthenticatedAttributes;
    UCHAR PlatformManifestID[32];
} MINCRYPT_CHAIN_INFO, *PMINCRYPT_CHAIN_INFO;

typedef struct _MINCRYPT_POLICY_INFO {
    ULONG cbSize;
    ULONG VerificationStatus;
    ULONG ulPolicyBits;
    PMINCRYPT_CHAIN_INFO pChainInfo;
    LARGE_INTEGER RevocationTime;
    LARGE_INTEGER NotValidBefore;
    LARGE_INTEGER NotValidAfter;
} MINCRYPT_POLICY_INFO, *PMINCRYPT_POLICY_INFO;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
CiCheckSignedFile (
    _In_ PUCHAR FileHash,
    _In_ ULONG HashLength,
    _In_ ALG_ID HashAlgorithm,
    _In_ PUCHAR CertBuffer,
    _In_ ULONG CertSize,
    _Out_ PMINCRYPT_POLICY_INFO PolicyInfo,
    _Out_opt_ PLARGE_INTEGER SigningTime,
    _Out_opt_ PMINCRYPT_POLICY_INFO TimeStampPolicyInfo
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
CiValidateFileObject (
    _In_ PFILE_OBJECT FileObject,
    _In_ ULONG SecureRequired,
    _In_ UCHAR RequestedSigningLevel,
    _Out_ PMINCRYPT_POLICY_INFO PolicyInfo,
    _Out_ PMINCRYPT_POLICY_INFO TimeStampPolicyInfo,
    _Out_ PLARGE_INTEGER SigningTime,
    _Out_ PUCHAR FileHash,
    _Inout_ PULONG FileHashSize,
    _Out_ PALG_ID FileHashAlgorithm
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
CiVerifyHashInCatalog (
    _In_ PUCHAR FileHash,
    _In_ ULONG HashLength,
    _In_ ALG_ID HashAlgorithm,
    _In_ ULONG Recheck,
    _In_ ULONG SecureProcess,
    _In_ ULONG AcceptRoots,
    _Out_opt_ PMINCRYPT_POLICY_INFO PolicyInfo,
    _Out_opt_ PUNICODE_STRING CatalogName,
    _Out_opt_ PLARGE_INTEGER SigningTime,
    _Out_opt_ PMINCRYPT_POLICY_INFO TimeStampPolicyInfo
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
VOID
NTAPI
CiFreePolicyInfo (
    _In_ PMINCRYPT_POLICY_INFO PolicyInfo
);

EXTERN_C_END

#endif
