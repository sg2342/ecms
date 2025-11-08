ecms
=====

[![Build Status](https://github.com/sg2342/ecms/workflows/Common%20Test/badge.svg)](https://github.com/sg2342/ecms/actions?query=branch%3Amain+workflow%3A"Common+Test")
[![Hex.pm](https://img.shields.io/hexpm/v/ecms.svg)](https://hex.pm/packages/ecms)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg?style=flat)](https://hexdocs.pm/ecms)

Sign, verify, encrypt, and decrypt RFC 5652 Cryptographic Message Syntax (CMS)
messages. Compatible with (some invocations of) the openSSL cms tool.

Sign / Verify
-----

ecms supports RSASSA-PSS, DSA, and EC signatures with SHA224, SHA256, SHA384, and
SHA512 digests in sign and verify.

Legacy RSA signatures and SHA1 digests are supported for **verify only**.

Encrypt / Decrypt
-----

RSAAES-OAEP `KeyTransRecipientInfo` and  EC (dhSinglePass-stdDH-sha224-kdf-scheme,
dhSinglePass-stdDH-sha256-kdf-scheme, dhSinglePass-stdDH-sha384-kdf-scheme,
dhSinglePass-stdDH-sha512-kdf-scheme) `KeyAgreeRecipientInfo`

`AuthEnvelopedData` with AES GCM 128, 224, and 256

`EnvelopedData` with AES OFB/CFB/CBC 128, 224, and 256

`KeyTransRecipientInfo` with `rsaEncryption` is supported.
