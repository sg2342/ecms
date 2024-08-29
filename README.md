ecms
=====

Sign, verify, encrypt, and decrypt RFC 5652 Cryptographic Message Syntax (CMS)
messages. Compatible with (some invocations of) the openSSL cms tool.

Sign / Verify
-----

ecms supports RSASSA-PSS, DSA, and EC signatures with SHA224, SHA256, SHA384, and
SHA512 digests in sign and verify.

Legacy RSA signatures and SHA1 digests are supported for **verify only**.

Encrypt / Decrypt
-----

RSAAES-OAEP `KeyAgreeRecipientInfo` and  EC (dhSinglePass-stdDH-sha224-kdf-scheme,
dhSinglePass-stdDH-sha256-kdf-scheme, dhSinglePass-stdDH-sha384-kdf-scheme,
dhSinglePass-stdDH-sha512-kdf-scheme) `KeyAgreeRecipientInfo`

`AuthEnvelopedData` with AES GCM 128, 224, and 256

`EnvelopedData` with AES OFB/CFB/CBC 128, 224, and 256

`KeyAgreeRecipientInfo` with `rsaEncryption` is supported for **decrypt only**.
