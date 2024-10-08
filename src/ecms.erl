-module(ecms).
-moduledoc """
Implementation of (parts of) RFC 5652 Cryptographic Message Syntax (CMS)
""".

-export([verify/2, sign/2, sign/3]).

-export([decrypt/3, encrypt/3, encrypt/2]).

-compile({nowarn_deprecated_function, [{public_key, decrypt_private, 3},
				       {public_key, encrypt_public, 3}]}).


-include_lib("public_key/include/public_key.hrl").

-doc """
DER encoded `'PrivateKeyInfo'`
""".
-type der_private_key() :: public_key:der_encoded().

-doc """
DER encoded X.509 `'Certificate'`
""".
-type der_certificate() :: public_key:der_encoded().

-type digest_type() :: crypto:sha2().
-type cert_info() :: {IssuerAndSerial :: map(),
		      SubjectKeyIdentifier :: binary() | false,
		      public_key:public_key()}.

-type cipher() :: aes_128_ofb |  aes_192_ofb |  aes_256_ofb |
		  aes_128_cfb128 | aes_192_cfb128 |  aes_256_cfb128 |
		  aes_128_cbc |  aes_192_cbc | aes_256_cbc.

-type cipher_aead() :: aes_128_gcm | aes_192_gcm | aes_256_gcm.

-export_type([der_private_key/0, der_certificate/0, cipher/0, cipher_aead/0,
	      digest_type/0]).

-doc """
Encrypt `Data` to `Recipients`

Equivalent to
`encrypt(Data, Recipients, #{ })`
""".
-spec encrypt(Data :: binary(),
	      Recipients :: [Certificate :: der_certificate(), ...]) ->
	  {ok, Encrypted :: binary()} | {error, _}.
encrypt(Data, Recipients) ->
    encrypt(Data, Recipients, #{ }).

-doc """
Encrypt `Data` to `Recipients`

When not set in `Opts`: `digest_type` defaults to `'sha256'` and `cipher` to
`'aes_256_cbc'`.

For `cipher` set to `'aes_128_gcm'`, `'aes_192_gcm'`, or `'aes_256_gcm'` the
encoded content is `AuthEnvelopedData` and `AuthAttributes` can be set as
`auth_attrs` in `Opts`.

The encoded recipientInfos contain a `KeyAgreeRecipientInfo` for each Elliptic Curve
certificate and a KeyTransRecipientInfo for each RSA certificate in `Recipients`.

`RSA-OAEP` is used in `KeyTransRecipientInfos`; the value of `digest_type` sets
the Hash and MaskGen algorithms.

`KeyAgreeRecipientInfo` uses RFC3394 AES Key Wrap and `dhSinglePass-stdDH` Key
Derivation, the value of `digest_type` sets Hash algorithm
""".
-spec encrypt(Data :: binary(),
	      Recipients :: [der_certificate()],
	      Opts :: #{ digest_type => digest_type(),
			 auth_attrs => [#{ attrType := tuple(),
					   attrValues := [binary()] }, ...],
			 cipher => cipher() | cipher_aead() }) ->
	  {ok, Encrypted :: binary()} | {error, _}.
encrypt(Data, Recipients, Opts0) ->
    Opts = maps:merge(#{ digest_type=> sha256,
			 cipher => aes_256_cbc }, Opts0),
    encrypt1(Data, Recipients, Opts).

-doc """
Decrypt CMS binary
""".
-spec decrypt(Encrypted :: binary(), RecipientCert :: der_certificate(),
	      RecipientKey :: der_private_key()) ->
	  {ok, Decrypted :: binary()} | {error, _}.
decrypt(Encrypted, RecipientCert, RecipientKey) ->
    IdEnvelopedData = 'CMS':'id-envelopedData'(),
    IdCtAuthEnvelopedData = 'CMS':'id-ct-authEnvelopedData'(),
    case 'CMS':decode('ContentInfo', Encrypted) of
	{ok, #{ contentType := IdEnvelopedData, content := Content }} ->
	    decrypt_envl(Content, RecipientCert, RecipientKey);
	{ok, #{ contentType := IdCtAuthEnvelopedData, content := Content }} ->
	    decrypt_auth(Content, RecipientCert, RecipientKey);
	{error, _} = E -> E
    end.

-doc """
Sign `Data` using `SignCert` and `SignKey`

Equivalent to
`sign(Data, #{ signers => [{SignCert, SignKey}])`
""".
-spec sign(Data :: binary(),
	   SignCert :: der_certificate(),
	   SignKey :: der_private_key()) ->
		  {ok, Signed :: binary()} | {error, _}.
sign(Data, SignCert, SignKey) ->
    sign(Data, #{ signers => [{SignCert, SignKey}] }).

-doc """
(re)sign `Data`

When not set in `Opts`: `digest_type` defaults to `sha256`, `signing_time` to
the current time, `resign` to `'false'` and `included_certs` to `[]`.

`digest_type` controls `DigestAlgorithm`, DSA/EC `SigatureAlgorithm` and for
RSA signatures also Hash and MaskGen algorithm in RSA-PSS parameters.

If `resign` is set to `'true'`, Data must contain `SignedData`. Additional
signatures from keys in `Signers`, the certificates in `Signers` and
any `included_certs` are added to the existing `SignedData`.
""".
-spec sign(Data :: binary(),
	   Opts :: #{ digest_type => digest_type(),
		      singning_time => calendar:datetime(),
		      resign => boolean(),
		      included_certs => [Certificate :: der_certificate()],
		      signers := [{SignCert :: der_certificate(),
				   SignKey :: der_private_key()}, ...]}) ->
	  {ok, Signed :: binary()} | {error, _}.
sign(Data, Opts) when is_map(Opts) ->
    sign1(Data,
	  maps:merge(#{ digest_type => sha256,
			singning_time => {date(), time()},
			resign => false,
			included_certs => [] }, Opts)).

-doc """
Verify CMS DER binary `InDER`

returns `{ok, EContent}` if at least one signature is from a certificate in
`Trusted` or from an included certificate that has been chain-validated against
a certificate in `Trusted`.
""".
-spec verify(InDER :: binary(),
	     Trusted :: [der_certificate(), ...]) ->
	  {ok, EContent :: binary()} | {error, _}.
verify(InDER, Trusted) ->
    IdSignedData = 'CMS':'id-signedData'(),
    IdData = 'CMS':'id-data'(),
    maybe
	{ok, #{ contentType := IdSignedData, content := SignedDataDER }} ?=
	    'CMS':decode('ContentInfo', InDER),
	{ok, #{ encapContentInfo := #{ eContentType := IdData,
				       eContent := EContent },
		signerInfos := SignerInfos } = SignedData} ?=
	    'CMS':decode('SignedData', SignedDataDER),

	Included = included_certificates(SignedData),
	{ok, Validated} ?= chain_validate(Included, Trusted),
	[_ | _] = Candidates ?=
	    lists:filtermap(
	      fun({ok, {IaS, SkI, PublicKey}}) ->
		      case lists:search(
			     fun(#{ sid := Sid }) ->
				     Sid =:= {issuerAndSerialNumber, IaS} orelse
					 Sid =:= {subjectKeyIdentifier, SkI} end,
			     SignerInfos) of
			  false -> false;
			  {value, Si} -> {true, {Si, PublicKey}} end
	      end, lists:map(fun decode_cert/1, Trusted ++ Validated)),
	true ?=
	    lists:any(
	      fun({#{ digestAlgorithm := #{ algorithm := DigestAlgOID },
		      signatureAlgorithm := SignatureAlgorithm,
		      signature := Signature } = SignerInfo,
		   Key}) ->
		      maybe
			  {ok, Opts} ?= pk_verify_opts(SignatureAlgorithm),
			  DigestType = oid(DigestAlgOID),
			  {ok, Digest} ?= digest(SignerInfo, DigestType, EContent),
			  public_key:verify({digest, Digest}, DigestType,
					    Signature, Key, Opts)
		      else _ -> false end end, Candidates),
	{ok, EContent}
    else {error,  _} = E -> E; _ -> {error, verify} end.

included_certificates(#{ certificates := [_ | _] = Certs }) ->
    L0 = ['PKIX1Explicit88':encode('Certificate', C) || {certificate, C} <- Certs],
    {_, L} = lists:unzip(L0),
    lists:usort(L);
included_certificates(_) -> [].

pk_verify_opts(#{ algorithm := ?'id-RSASSA-PSS', parameters := Parameters}) ->
    maybe
	{ok, #{ maskGenAlgorithm := #{ algorithm := ?'id-mgf1',
				       parameters := MgParameters},
		saltLength := SaltLength }} ?=
	    'PKIX1-PSS-OAEP-Algorithms':decode('RSASSA-PSS-params', Parameters),
	{ok, #{ algorithm := AlgOId }} ?=
	    'PKIX1-PSS-OAEP-Algorithms':decode('MaskGenAlgorithm', MgParameters),
	{ok, [{rsa_padding, rsa_pkcs1_pss_padding},
	      {rsa_mgf1_md, oid(AlgOId)},
	      {rsa_pss_saltlen, SaltLength}]}
    else _ -> {error, pk_verify_opts} end;
pk_verify_opts(_) -> {ok, []}.

digest(#{ signedAttrs := SignedAttrs }, DigestType, SignedData) ->
    Digest = crypto:hash(DigestType, SignedData),
    IdMessageDigest = 'CMS':'id-messageDigest'(),
    maybe
	[MessageDigestDER] ?=
	    [V || #{ attrType := AttrType, attrValues := [V]} <- SignedAttrs,
		  AttrType =:= IdMessageDigest],
	{ok, Digest} ?= 'CMS':decode('Digest', MessageDigestDER),
	{ok, SignedAttrsDER} ?= 'CMS':encode('SignedAttributes', SignedAttrs),
	{ok, crypto:hash(DigestType, SignedAttrsDER)}
    else _ -> {error, digest} end;
digest(#{}, DigestType, SignedData) -> {ok, crypto:hash(DigestType, SignedData)}.

%% return all certs in `Included` that where chain-validated
%% against certs in `Trusted` using intermediate certs from
%% `Included`
-spec chain_validate(Included :: [der_certificate()],
		     Trusted :: [der_certificate()]) ->
	  {ok, Valid :: [der_certificate()]} | {error, _}.
chain_validate(Included, Trusted) ->
    try
	{ok, lists:filtermap(
	       fun([C | _] = Chain) ->
		       maybe
			   [T] ?= [V || V <- Trusted,
					public_key:pkix_is_issuer(C, V)],
			   {ok, _} ?= public_key:pkix_path_validation(T, Chain, []),
			   {true, lists:last(Chain)}
		       else _ -> false end end,
	       [build_chain([C], Included -- [C]) || C <- Included])}
    catch error:_ -> {error, der_decode_cert} end.

build_chain([Cert | _] = Chain, Certs) ->
    case lists:filter(
	   fun(C) -> public_key:pkix_is_issuer(Cert, C) end, Certs) of
	[] -> Chain;
	[IM] -> build_chain([IM | Chain], Certs -- [IM]) end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% encrypt implementation
%%%
encrypt1(Data, Recipients, #{ cipher := Cipher, digest_type := DigestType } = Opts)
  when Cipher =:= aes_128_gcm ; Cipher =:= aes_192_gcm ; Cipher =:= aes_256_gcm ->
    #{ key_length := KeyLength, iv_length := IvLength } =
	crypto:cipher_info(Cipher),
    <<CEK:KeyLength/binary, IV:IvLength/binary>> =
	crypto:strong_rand_bytes(KeyLength + IvLength),
    MAClen = 16,
    {M0, AAD} =
	case maps:is_key(auth_attrs, Opts) of
	    false -> {#{}, <<>>};
	    true ->
		AAttrs = maps:get(auth_attrs, Opts),
		{ok, AuthAttrsDER} = 'CMS':encode('AuthAttributes', AAttrs),
		{ #{ authAttrs => AAttrs }, AuthAttrsDER }
	end,
    {EncryptedContent, MAC} =
	crypto:crypto_one_time_aead(Cipher, CEK, IV, Data, AAD, MAClen, true),
    maybe
	{ok, RecipientInfos} ?=
	    recipient_infos(lists:map(fun decode_cert/1, Recipients),
			    {CEK, DigestType, KeyLength}, []),
	{ok, Parameters} ?=
	    'CMS':encode('GCMParameters',
			 #{'aes-nonce' => IV, 'aes-ICVlen' => MAClen}),
	AuthEnvelopedData =
	    M0#{ version => v0,
		 recipientInfos => RecipientInfos,
		 mac => MAC,
		 authEncryptedContentInfo =>
		     #{ contentType => 'CMS':'id-data'(),
			contentEncryptionAlgorithm =>
			    #{ algorithm => oid(Cipher), parameters => Parameters},
			encryptedContent => EncryptedContent
		      } },
	{ok, AuthEnvelopedDataDER} ?= 'CMS':encode('AuthEnvelopedData', AuthEnvelopedData),
	'CMS':encode('ContentInfo', #{ contentType => 'CMS':'id-ct-authEnvelopedData'(),
				       content => AuthEnvelopedDataDER })
    else {error, _} = E -> E end;
encrypt1(Data, Recipients, #{ cipher := Cipher, digest_type := DigestType }) ->
    #{ key_length := KeyLength, block_size := BlockSize, iv_length := IvLength } =
	crypto:cipher_info(Cipher),
    <<CEK:KeyLength/binary, IV:IvLength/binary>> =
	crypto:strong_rand_bytes(KeyLength + IvLength),
    EncryptedContent =
	crypto:crypto_one_time(Cipher, CEK, IV, pad(Data, BlockSize), true),
    maybe
	{ok, RecipientInfos} ?=
	    recipient_infos(lists:map(fun decode_cert/1, Recipients),
			    {CEK, DigestType, KeyLength}, []),
	EnvelopedData =
	    #{ version => v2,
	       recipientInfos => RecipientInfos,
	       encryptedContentInfo =>
		   #{ contentType => 'CMS':'id-data'(),
		      contentEncryptionAlgorithm =>
			  #{ algorithm => oid(Cipher),
			     parameters => <<4, IvLength, IV/binary>>},
		      encryptedContent => EncryptedContent } },
	{ok, EnvelopedDataDER} ?= 'CMS':encode('EnvelopedData', EnvelopedData),
	'CMS':encode('ContentInfo', #{ contentType => 'CMS':'id-envelopedData'(),
				       content => EnvelopedDataDER})
    else {error, _} = E -> E end.

-spec recipient_infos([{ok, cert_info()} | {error, _}],
		      {CEK :: binary(), digest_type(), KeyLength :: pos_integer()}, Acc) ->
	  {ok, Acc} | {error, _} when Acc :: [{kari, #{}} | {ktri, #{}}].
recipient_infos([], _P, Acc) -> {ok, lists:reverse(Acc)};
recipient_infos([{error, _} = E | _], _, _) -> E;
recipient_infos([{ok, {IaS, SkI,  #'RSAPublicKey'{} = RsaPub}} | T], P, Acc) ->
    {CEK, DigestType, _} = P,
    {RId, Version} =
	case SkI of
	    false -> {{issuerAndSerialNumber, IaS}, v0};
	    _ -> {{subjectKeyIdentifier, SkI}, v2} end,
    Alg = #{ algorithm => oid(DigestType) },
    {ok, MaskGenP} = 'PKIX1-PSS-OAEP-Algorithms':encode('MaskGenAlgorithm', Alg),
    KeyEncryptionParameters =
	#{ hashFunc => Alg,
	   maskGenFunc => #{ algorithm => 'PKIX1-PSS-OAEP-Algorithms':'id-mgf1'(),
			     parameters => MaskGenP } },
    Opts = [{rsa_padding, rsa_pkcs1_oaep_padding},
	    {rsa_mgf1_md, DigestType}, {rsa_oaep_md, DigestType}],
    EncryptedKey = public_key:encrypt_public(CEK, RsaPub, Opts),
    {ok, KeyEncryptionParametersDER} =
	'PKIX1-PSS-OAEP-Algorithms':encode('RSAES-OAEP-params', KeyEncryptionParameters),
    R = {ktri,
	 #{ version => Version,
	    keyEncryptionAlgorithm => #{ algorithm => ?'id-RSAES-OAEP',
					 parameters => KeyEncryptionParametersDER },
	    rid => RId,
	    encryptedKey => EncryptedKey }},
    recipient_infos(T, P, [R | Acc]);
recipient_infos([{ok, {IaS, SkI,  {#'ECPoint'{} = EcPub, EcParameters}}} | T],
		{CEK, DigestType, KeyLength} = P, Acc) ->
    RId = case SkI of
	      false -> {issuerAndSerialNumber, IaS};
	      _ -> {rKeyId, #{ subjectKeyIdentifier => SkI }} end,
    Algorithm = case DigestType of
		    sha224 -> 'CMS':'dhSinglePass-stdDH-sha224kdf-scheme'();
		    sha256 -> 'CMS':'dhSinglePass-stdDH-sha256kdf-scheme'();
		    sha384 -> 'CMS':'dhSinglePass-stdDH-sha384kdf-scheme'();
		    sha512 -> 'CMS':'dhSinglePass-stdDH-sha512kdf-scheme'()
		end,
    KeyEncryptionParameters =
	case KeyLength of
	    32 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 45>>; % aes256-wrap
	    24 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 25>>; % aes192-wrap
	    16 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 5>>   % aes128-wrap
	end,
    Ukm = crypto:strong_rand_bytes(42),
    {ok, SharedInfo} = encode_shared_info(KeyEncryptionParameters, Ukm, KeyLength),
    #'ECPrivateKey'{ publicKey = OriginatorKey } = EcPriv =
	public_key:generate_key(EcParameters),
    Z = public_key:compute_key(EcPub, EcPriv),
    KEK = x963_kdf(DigestType, Z, SharedInfo, KeyLength),
    RecipientEncryptedKeys =
	[#{ encryptedKey => rfc3394:wrap(CEK, KEK), rid => RId }],
    R = {kari,
	 #{ version => v3,
	    originator =>
		{originatorKey,
		 #{ algorithm => #{ algorithm => ?'id-ecPublicKey' },
		    publicKey => OriginatorKey }},
	    ukm => Ukm,
	    keyEncryptionAlgorithm =>
		#{ algorithm => Algorithm, parameters => KeyEncryptionParameters },
	    recipientEncryptedKeys => RecipientEncryptedKeys }},
    recipient_infos(T, P, [R | Acc]);
recipient_infos(_, _P, _Acc) -> {error, unsupported_key_type}.

pad(Data, 1) -> Data;
pad(Data, N) ->
    Pad = N - (erlang:byte_size(Data) rem N),
    <<Data/binary, (binary:copy(<<Pad>>, Pad))/binary>>.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% decrypt implementation
%%%
decrypt_envl(Content, RecipientCertDER, RecipientKeyDER) ->
    IdData = 'CMS':'id-data'(),
    maybe
	{ok, #{ %% version := Version,
		recipientInfos := RecipientInfos,
		encryptedContentInfo :=
		    #{ contentType := IdData,
		       contentEncryptionAlgorithm :=
			   #{ algorithm := Algorithm,
			      parameters := <<4, IVlen, IV:IVlen/binary>> },
		       encryptedContent := EncryptedContent }}} ?=
	    'CMS':decode('EnvelopedData', Content),
	Cipher = oid(Algorithm),
	#{ key_length := KeyLength, block_size := BlockSize } =
	    crypto:cipher_info(Cipher),
	{ok, CEK} ?= cek(RecipientCertDER, RecipientKeyDER, RecipientInfos, KeyLength),
	{ok, unpad(crypto:crypto_one_time(Cipher, CEK, IV, EncryptedContent, false),
		   BlockSize)}
    else {error, _} = E -> E end.

decrypt_auth(Content, RecipientCertDER, RecipientKeyDER) ->
    IdData = 'CMS':'id-data'(),
    maybe
	{ok, #{ version := v0,
		recipientInfos := RecipientInfos,
		mac := MAC,
		authEncryptedContentInfo :=
		    #{ contentType := IdData,
		       contentEncryptionAlgorithm :=
			   #{ algorithm := Algorithm,
			      parameters := Parameters },
		       encryptedContent := EncryptedContent } } = M } ?=
	    'CMS':decode('AuthEnvelopedData', Content),
	Cipher = oid(Algorithm),
	MAClen = byte_size(MAC),
	{ok, #{'aes-nonce' := Nonce, 'aes-ICVlen' := MAClen}} ?=
	    'CMS':decode('GCMParameters', Parameters),
	#{ key_length := KeyLength } = crypto:cipher_info(Cipher),
	{ok, CEK} ?= cek(RecipientCertDER, RecipientKeyDER, RecipientInfos, KeyLength),
	{ok, AAD} ?=
	    case maps:is_key(authAttrs, M) of
		false -> {ok, <<>>};
		true -> 'CMS':encode('AuthAttributes', maps:get(authAttrs, M))
	    end,
	case crypto:crypto_one_time_aead(Cipher, CEK, Nonce, EncryptedContent,
					 AAD, MAC, false) of
	    error -> {error, aead_decrypt_failed};
	    Plain -> {ok, Plain}
	end
    else {error, _} = E -> E end.

-spec cek(der_certificate(), der_private_key(), RecipientInfos :: [map()],
	  KeyLength :: pos_integer()) -> {ok, CEK :: binary()} | {error, _}.
cek(RecipientCertDER, RecipientKeyDER, RecipientInfos, KeyLength) ->
    maybe
	{ok, {IaS, SkI, _}} ?= decode_cert(RecipientCertDER),
	{ok, RecipientKey} ?= decode_private_key(RecipientKeyDER),
	case in_kari_or_ktri(RecipientInfos, {IaS, SkI}) of
	    {ok, {OriginatorKey, Ukm, KeyEncryptionAlgorithm,
		  KeyEncryptionParameters, EncryptedKey}} ->
		cec_ec(OriginatorKey, Ukm, KeyEncryptionAlgorithm,
		       KeyEncryptionParameters, EncryptedKey,
		       RecipientKey, KeyLength);
	    {ok, {?'rsaEncryption', <<5, 0>>, EncryptedKey}} ->
		{ok, public_key:decrypt_private(EncryptedKey, RecipientKey, [])};
	    {ok, {?'id-RSAES-OAEP', ParametersDER, EncryptedKey}} ->
		MaybeParams =
		    'PKIX1-PSS-OAEP-Algorithms':decode('RSAES-OAEP-params',
						       ParametersDER),
		cec_oaep(EncryptedKey, MaybeParams, RecipientKey);
	    {error, _} = E0 -> E0 end
    else {error, _} = E -> E end.

cec_oaep(_, {error, _} = E, _) -> E;
cec_oaep(EncryptedKey, {ok, #{ hashFunc := #{ algorithm := AlgorithmId } }},
	 RecipientKey) ->
    Alg = oid(AlgorithmId),
    Opts = [{rsa_padding, rsa_pkcs1_oaep_padding},
	    {rsa_mgf1_md, Alg}, {rsa_oaep_md, Alg}],
    {ok, public_key:decrypt_private(EncryptedKey, RecipientKey, Opts)}.

cec_ec(OriginatorKey, Ukm, KeyEncryptionAlgorithm, KeyEncryptionParameters,
       EncryptedKey, RecipientKey, KeyLength) ->
    DhSinglePassStdDHSha224kdfScheme = 'CMS':'dhSinglePass-stdDH-sha224kdf-scheme'(),
    DhSinglePassStdDHSha256kdfScheme = 'CMS':'dhSinglePass-stdDH-sha256kdf-scheme'(),
    DhSinglePassStdDHSha384kdfScheme = 'CMS':'dhSinglePass-stdDH-sha384kdf-scheme'(),
    DhSinglePassStdDHSha512kdfScheme = 'CMS':'dhSinglePass-stdDH-sha512kdf-scheme'(),
    DhSinglePassStdDHSha1kdfScheme = 'CMS':'dhSinglePass-stdDH-sha1kdf-scheme'(),
    maybe
	{ok, DigestType} ?= case KeyEncryptionAlgorithm of
				DhSinglePassStdDHSha224kdfScheme -> {ok, sha224};
				DhSinglePassStdDHSha256kdfScheme -> {ok, sha256};
				DhSinglePassStdDHSha384kdfScheme -> {ok, sha384};
				DhSinglePassStdDHSha512kdfScheme -> {ok, sha512};
				DhSinglePassStdDHSha1kdfScheme -> {ok, sha};
				_ -> {error, unsupported_key_encryption}
			    end,
	{ok, SharedInfo} ?= encode_shared_info(KeyEncryptionParameters,
					       Ukm, KeyLength),
	Z = public_key:compute_key(#'ECPoint'{point = OriginatorKey}, RecipientKey),
	KEK = x963_kdf(DigestType, Z, SharedInfo, KeyLength),
	try
	    {ok, rfc3394:unwrap(EncryptedKey, KEK)}
	catch error:iv_mismatch -> {error, iv_mismatch} end
    else {error, _} = E1 -> E1 end.

in_kari_or_ktri([], _IaSandSkI) -> {error, no_matching_kari_or_ktri};
in_kari_or_ktri([{ktri,
		  #{ version := v0,
		     keyEncryptionAlgorithm :=
			 #{ algorithm := KeyEncryptionAlgorithm,
			    parameters := KeyEncryptionParameters },
		     encryptedKey := EncryptedKey,
		     rid := {issuerAndSerialNumber, IaS}
		   } } | _], {IaS, _SkI}) ->
    {ok, {KeyEncryptionAlgorithm, KeyEncryptionParameters, EncryptedKey}};
in_kari_or_ktri([{ktri,
		  #{ version := v2,
		     keyEncryptionAlgorithm :=
			 #{ algorithm := KeyEncryptionAlgorithm,
			    parameters := KeyEncryptionParameters },
		     encryptedKey := EncryptedKey,
		     rid := {subjectKeyIdentifier, SkI}
		   } } | _], {_IaS, SkI}) ->
    {ok, {KeyEncryptionAlgorithm, KeyEncryptionParameters, EncryptedKey}};
in_kari_or_ktri([{ktri, _} | T], IaSandSkI) -> in_kari_or_ktri(T, IaSandSkI);
in_kari_or_ktri([{kari,
		  #{ version := v3,
		     keyEncryptionAlgorithm :=
			 #{ algorithm := KeyEncryptionAlgorithm,
			    parameters := KeyEncryptionParameters },
		     originator :=
			 {originatorKey,
			  #{ algorithm :=
				 #{ algorithm := ?'id-ecPublicKey' },
			     publicKey := OriginatorKey } },
		     recipientEncryptedKeys := RecipientEncryptedKeys
		   } = Kari} | T], {IaS, SkI}) ->
    Ukm = case maps:is_key(ukm, Kari) of
	      false -> false;
	      true -> maps:get(ukm, Kari) end,
    case lists:search(
	   fun(#{ rid := {rKeyId, #{ subjectKeyIdentifier := Id }} }) ->
		   Id =:= SkI;
	      (#{ rid := {issuerAndSerialNumber, Id} }) -> IaS =:= Id end,
	   RecipientEncryptedKeys) of
	false ->  in_kari_or_ktri(T, {IaS, SkI});
	{value, #{ encryptedKey := EncryptedKey } } ->
	    {ok, {OriginatorKey, Ukm, KeyEncryptionAlgorithm,
		  KeyEncryptionParameters, EncryptedKey}}
    end.

unpad(Data, 1) -> Data;
unpad(Data, N) ->
    SLen = ((erlang:byte_size(Data) div N) - 1) * N,
    <<S:SLen/binary, E/binary>> = Data,
    <<_:15/binary, Pad>> = E,
    RLen = N - Pad,
    <<R:RLen/binary, _/binary>> = E,
    <<S/binary, R/binary>>.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% sign implementation
%%%
sign1(InDER, #{ resign := true, included_certs := IncludedCerts0 } = Opts0) ->
    IdSignedData = 'CMS':'id-signedData'(),
    IdData = 'CMS':'id-data'(),
    maybe
	{ok, #{ contentType := IdSignedData, content := SignedDataDER }} ?=
	    'CMS':decode('ContentInfo', InDER),
	{ok, #{ encapContentInfo := #{ eContentType := IdData,
				       eContent := Content },
	        signerInfos := SignerInfos,
		digestAlgorithms := DigestAlgorithms,
	        crls := Crls,
	        certificates := Certs0 }} ?=
	    'CMS':decode('SignedData', SignedDataDER),
	Certs1 = ['PKIX1Explicit88':encode('Certificate', C) ||
		     {certificate, C} <- Certs0],
	{_, Certs} = lists:unzip(Certs1),
	IncludedCerts = Certs ++ IncludedCerts0,
	Opts = Opts0#{ resign => false,
		       included_certs => IncludedCerts },
	sign2(Content, SignerInfos, DigestAlgorithms, Crls, Opts)
    else {error, _} = E -> E end;
sign1(Content, Opts) -> sign2(Content, [], [], [], Opts).

sign2(Content, SignerInfos0, DigestAlgorithms0, Crls,
      #{ digest_type := DigestType,
	 singning_time := SigningTime,
	 included_certs := IncludedCertsDER,
	 signers := Signers }) ->
    maybe
	ContentDigest = crypto:hash(DigestType, Content),
	{ok, ContentTypeDER} ?= 'CMS':encode('ContentType', 'CMS':'id-data'()),
	{ok, MessageDigestDER} ?= 'CMS':encode('Digest', ContentDigest),
	{ok, SigningTimeDER} ?= 'CMS':encode('SigningTime',
					    {generalTime, fmt_datetime(SigningTime)}),
	SignedAttrs =
	    [#{ attrType => 'CMS':'id-contentType'(),
		attrValues => [ContentTypeDER] },
	     #{ attrType => 'CMS':'id-signingTime'(),
		attrValues => [SigningTimeDER] },
	     #{ attrType => 'CMS':'id-messageDigest'(),
		attrValues => [MessageDigestDER] }],
	{ok, SignedAttrsDER} ?= 'CMS':encode('SignedAttributes', SignedAttrs),
	Digest = crypto:hash(DigestType, SignedAttrsDER),
	{ok, SignerInfos} ?= signer_infos(Signers, Digest, DigestType, SignedAttrs, []),

	DigestAlgorithms = lists:usort([A || #{ digestAlgorithm := A } <- SignerInfos]
				       ++ DigestAlgorithms0),

	{CertsDER, _} = lists:unzip(Signers),
	IncludedCerts1 = ['PKIX1Explicit88':decode('Certificate', C) ||
			     C <- IncludedCertsDER ++ CertsDER],
	IncludedCerts = lists:usort([{certificate, C} || {ok, C} <- IncludedCerts1]),

	{ok, SignedDataDER} ?=
	    'CMS':encode('SignedData',
			 #{ version => v3,
			    digestAlgorithms => DigestAlgorithms,
			    certificates => IncludedCerts,
			    crls => Crls,
			    signerInfos => SignerInfos ++ SignerInfos0,
			    encapContentInfo =>
				#{ eContentType => 'CMS':'id-data'(),
				   eContent => Content } }),
	'CMS':encode('ContentInfo', #{ contentType => 'CMS':'id-signedData'(),
				       content => SignedDataDER})
    else {error, _} = E -> E end.

-spec signer_infos([{der_certificate(), der_private_key()}], Digest :: binary(),
		   digest_type(), SignedAttrs :: [map()], SignerInfos0 :: [map()]) ->
	  {ok, SignerInfos :: [map()]} | {error, _}.
signer_infos([], _Digest, _DigestType, _SignedAttrs, SignerInfos) ->
    {ok, SignerInfos};
signer_infos([{CertDER, KeyDER} | T], Digest, DigestType, SignedAttrs, SignerInfos0) ->
    maybe
	{ok, #{ tbsCertificate := TbsCertificate }}
	    ?= 'PKIX1Explicit88':decode('Certificate', CertDER),
	{ok, Key} ?= decode_private_key(KeyDER),
	{DigestAlgorithm, {SignatureAlgorithm, Opts}} =
	    sign_algs(DigestType, Key),
	IaS = maps:with([serialNumber, issuer], TbsCertificate),
	Signature = public_key:sign({digest, Digest}, DigestType, Key, Opts),
	Si = #{ version => v1,
		sid => {issuerAndSerialNumber, IaS},
		digestAlgorithm => DigestAlgorithm,
		signatureAlgorithm => SignatureAlgorithm,
		signature => Signature,
		signedAttrs => SignedAttrs
	      },
	signer_infos(T, Digest, DigestType, SignedAttrs, [Si | SignerInfos0])
    end.

-define('id-dsa-with-sha512', {2, 16, 840, 1, 101, 3, 4, 3, 4}).
-define('id-dsa-with-sha384', {2, 16, 840, 1, 101, 3, 4, 3, 3}).

sign_algs(H, K) -> { #{ algorithm => oid(H) }, sign_algs1(H, K) }.

sign_algs1(sha512, #'DSAPrivateKey'{}) -> {#{ algorithm => ?'id-dsa-with-sha512' }, []};
sign_algs1(sha384, #'DSAPrivateKey'{}) -> {#{ algorithm => ?'id-dsa-with-sha384' }, []};
sign_algs1(sha256, #'DSAPrivateKey'{}) -> {#{ algorithm => ?'id-dsa-with-sha256' }, []};
sign_algs1(sha224, #'DSAPrivateKey'{}) -> {#{ algorithm => ?'id-dsa-with-sha224' }, []};
sign_algs1(sha512, #'ECPrivateKey'{}) -> {#{ algorithm => ?'ecdsa-with-SHA512' }, []};
sign_algs1(sha384, #'ECPrivateKey'{}) -> {#{ algorithm => ?'ecdsa-with-SHA384' }, []};
sign_algs1(sha256, #'ECPrivateKey'{}) -> {#{ algorithm => ?'ecdsa-with-SHA256' }, []};
sign_algs1(sha224, #'ECPrivateKey'{}) -> {#{ algorithm => ?'ecdsa-with-SHA224' }, []};
sign_algs1(H, #'RSAPrivateKey'{}) ->
    #{ size := SaltLength } = crypto:hash_info(H),
    Opts = [{rsa_padding, rsa_pkcs1_pss_padding},
	    {rsa_mgf1_md, H},
	    {rsa_pss_saltlen, SaltLength}],
    Alg = #{ algorithm => oid(H), parameters => <<5, 0>> },
    {ok, MgParameters} = 'PKIX1-PSS-OAEP-Algorithms':encode('MaskGenAlgorithm', Alg),
    Parameters = #{ hashAlgorithm => Alg,
		    maskGenAlgorithm =>
			#{ algorithm => ?'id-mgf1', parameters => MgParameters },
		    saltLength => SaltLength, trailerField => 1 },
    {ok, ParametersDER } =
	'PKIX1-PSS-OAEP-Algorithms':encode('RSASSA-PSS-params', Parameters),
    { #{ algorithm =>  ?'id-RSASSA-PSS', parameters => ParametersDER }, Opts}.

-spec fmt_datetime(calendar:datetime()) -> string().
fmt_datetime({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    lists:flatten(io_lib:format("~w~2..0w~2..0w~2..0w~2..0w~2..0wZ",
				[Year, Month, Day, Hour, Minute, Second])).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% common code
%%%
-spec x963_kdf(digest_type(), Key :: binary(),
	       Info :: binary(), Length :: pos_integer()) -> KEK :: binary().
x963_kdf(Hash, Key, Info, Length) ->
    #{ size := Size } = crypto:hash_info(Hash),
    Bin = << <<(crypto:hash(Hash, <<Key/binary, I:32, Info/binary>>))/binary >>
	     || I <- lists:seq(1, ceil(Length / Size)) >>,
    binary:part(Bin, 0, Length).

-spec encode_shared_info(WrapAlgDER :: binary(), Ukm :: binary() | false,
			 KeyLength :: pos_integer()) ->
	  {ok, SharedInfo :: binary()} | {error, _}.
encode_shared_info(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 45>>, Ukm, KeyLength) ->
    encode_shared_info1(?'id-aes256-wrap', Ukm, KeyLength);
encode_shared_info(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 25>>, Ukm, KeyLength) ->
    encode_shared_info1(?'id-aes192-wrap', Ukm, KeyLength);
encode_shared_info(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 5>>, Ukm, KeyLength) ->
    encode_shared_info1(?'id-aes128-wrap', Ukm, KeyLength).

encode_shared_info1(WrapAlg, Ukm, KeyLength) ->
    SharedInfo0 = #{ keyInfo => #{ algorithm => WrapAlg },
		     suppPubInfo => <<(KeyLength * 8):32>> },
    SharedInfo  = case Ukm of
		      false -> SharedInfo0;
		      V -> SharedInfo0#{ entityUInfo => V } end,
    'CMS':encode('ECC-CMS-SharedInfo', SharedInfo).

-spec decode_cert(der_certificate()) ->
	  {ok, cert_info()} | {error, _}.
decode_cert(DER) ->
    IdCeSubjectKeyIdentifier = 'CMS':'id-ce-subjectKeyIdentifier'(),
    maybe
	{ok, #'OTPCertificate'{
		tbsCertificate =
		    #'OTPTBSCertificate'{
		       subjectPublicKeyInfo =
			   #'OTPSubjectPublicKeyInfo'{
			      algorithm =
				  #'PublicKeyAlgorithm'{parameters = Parameters},
			      subjectPublicKey = PubKey0} } }} ?=
	    try {ok, public_key:pkix_decode_cert(DER, otp)}
	    catch error:_ -> {error, der_decode_cert} end,
	PubKey =
	    case {PubKey0, Parameters} of
		{#'RSAPublicKey'{} = RsaPK, _} ->  RsaPK;
		{DsaPK, {params, #'Dss-Parms'{} = Params}} -> {DsaPK, Params};
		{#'ECPoint'{} = Point, Params} -> {Point, Params}
	    end,
	{ok, #{ tbsCertificate := TbsCertificate }} ?=
	    'PKIX1Explicit88':decode('Certificate', DER),
	IaS = maps:with([serialNumber, issuer], TbsCertificate),
	Extensions = case maps:is_key(extensions, TbsCertificate) of
			 false -> [];
			 true -> maps:get(extensions, TbsCertificate) end,
	{ok, SkI} ?=
	    case lists:search(
		   fun(#{ extnID := Id }) -> Id == IdCeSubjectKeyIdentifier end,
		   Extensions) of
		false -> {ok, false};
		{value, #{ extnValue := ExtnValue } } ->
		    'CMS':decode('SubjectKeyIdentifier', ExtnValue)
	    end,
	{ok, {IaS, SkI, PubKey}}
    else {error, _} = E -> E end.

-spec decode_private_key(der_private_key()) ->
	  {ok, public_key:private_key()} | {error, _}.
decode_private_key(DER) ->
    try {ok, public_key:der_decode('PrivateKeyInfo', DER)}
    catch error:_ -> {error, der_decode_private_key} end.

-spec oid(OID :: tuple()) -> digest_type() | sha | cipher() | cipher_aead();
	 (digest_type() | cipher() | cipher_aead()) -> OID :: tuple().
oid(?'id-sha1') -> sha;
oid(?'id-sha512') -> sha512;
oid(?'id-sha384') -> sha384;
oid(?'id-sha256') -> sha256;
oid(?'id-sha224') -> sha224;
oid({2, 16, 840, 1, 101, 3, 4, 1, 3}) ->  aes_128_ofb;
oid({2, 16, 840, 1, 101, 3, 4, 1, 23}) -> aes_192_ofb;
oid({2, 16, 840, 1, 101, 3, 4, 1, 43}) -> aes_256_ofb;
oid({2, 16, 840, 1, 101, 3, 4, 1, 4}) ->  aes_128_cfb128;
oid({2, 16, 840, 1, 101, 3, 4, 1, 24}) -> aes_192_cfb128;
oid({2, 16, 840, 1, 101, 3, 4, 1, 44}) -> aes_256_cfb128;
oid({2, 16, 840, 1, 101, 3, 4, 1, 6}) ->  aes_128_gcm;
oid({2, 16, 840, 1, 101, 3, 4, 1, 26}) -> aes_192_gcm;
oid({2, 16, 840, 1, 101, 3, 4, 1, 46}) -> aes_256_gcm;
oid(?'id-aes128-CBC') -> aes_128_cbc;
oid(?'id-aes192-CBC') -> aes_192_cbc;
oid(?'id-aes256-CBC') -> aes_256_cbc;
oid(sha512) -> ?'id-sha512';
oid(sha384) -> ?'id-sha384';
oid(sha256) -> ?'id-sha256';
oid(sha224) -> ?'id-sha224';
oid(aes_128_ofb) -> {2, 16, 840, 1, 101, 3, 4, 1, 3};
oid(aes_192_ofb) -> {2, 16, 840, 1, 101, 3, 4, 1, 23};
oid(aes_256_ofb) -> {2, 16, 840, 1, 101, 3, 4, 1, 43};
oid(aes_128_cfb128) -> {2, 16, 840, 1, 101, 3, 4, 1, 4};
oid(aes_192_cfb128) -> {2, 16, 840, 1, 101, 3, 4, 1, 24};
oid(aes_256_cfb128) -> {2, 16, 840, 1, 101, 3, 4, 1, 44};
oid(aes_128_gcm) -> {2, 16, 840, 1, 101, 3, 4, 1, 6};
oid(aes_192_gcm) -> {2, 16, 840, 1, 101, 3, 4, 1, 26};
oid(aes_256_gcm) -> {2, 16, 840, 1, 101, 3, 4, 1, 46};
oid(aes_128_cbc) -> ?'id-aes128-CBC';
oid(aes_192_cbc) -> ?'id-aes192-CBC';
oid(aes_256_cbc) -> ?'id-aes256-CBC'.
