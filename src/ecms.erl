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
Sign `Data` using `SignCert` and `SignKey`
""".
-spec sign(Data :: binary(),
	   SignCert :: public_key:der_encoded(),
	   SignKey :: public_key:der_encoded()) ->
	  {ok, Signed :: binary()} | {error, _}.
sign(Data, SignCert, SignKey) ->
    sign(Data, #{ signers => [{SignCert, SignKey}] }).


-doc """
sign `Data`
""".
-spec sign(Data :: binary(),
	   Opts :: #{ digest_type => crypto:sha2(),
		      singning_time => calendar:datetime(),
		      resign => boolean(),
		      included_certs => [Certificate :: public_key:der_encoded()],
		      signers := [{SignCert :: public_key:der_encoded(),
				   SignKey :: public_key:der_encoded()}]
		    }) ->
	  {ok, Signed :: binary()} | {error, _}.
sign(Data, Opts) when is_map(Opts) ->
    sign1(Data,
	  maps:merge(#{ digest_type => sha256,
			singning_time => {date(), time()},
			resign => false,
			included_certs => [] }, Opts)).

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
	{ok, ContentTypeDER} = 'CMS':encode('ContentType', 'CMS':'id-data'()),
	{ok, MessageDigestDER} = 'CMS':encode('Digest', ContentDigest),
	{ok, SigningTimeDER} = 'CMS':encode('SigningTime',
					    {generalTime, fmt_datetime(SigningTime)}),
	SignedAttrs =
	    [#{ attrType => 'CMS':'id-contentType'(),
		attrValues => [ContentTypeDER] },
	     #{ attrType => 'CMS':'id-signingTime'(),
		attrValues => [SigningTimeDER] },
	     #{ attrType => 'CMS':'id-messageDigest'(),
		attrValues => [MessageDigestDER] }],
	{ok, SignedAttrsDER} = 'CMS':encode('SignedAttributes', SignedAttrs),
	Digest = crypto:hash(DigestType, SignedAttrsDER),
	{ok, SignerInfos} ?= sign3(Signers, Digest, DigestType, SignedAttrs, []),

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

sign3([], _Digest, _DigestType, _SignedAttrs, SignerInfos) ->
    {ok, SignerInfos};
sign3([{CertDER, KeyDER} | T], Digest, DigestType, SignedAttrs, SignerInfos0) ->
    maybe
	{ok, #{ tbsCertificate := TbsCertificate }}
	    ?= 'PKIX1Explicit88':decode('Certificate', CertDER),
	Key = public_key:der_decode('PrivateKeyInfo', KeyDER),
	{DigestAlgorithm, SignatureAlgorithm} =
	    sign_algs(DigestType, Key),
	IaS = maps:with([serialNumber, issuer], TbsCertificate),
	Signature = public_key:sign({digest, Digest}, DigestType, Key),
	Si = #{ version => v1,
		sid => {issuerAndSerialNumber, IaS},
		digestAlgorithm => DigestAlgorithm,
		signatureAlgorithm => SignatureAlgorithm,
		signature => Signature,
		signedAttrs => SignedAttrs
	      },
	sign3(T, Digest, DigestType, SignedAttrs, [Si | SignerInfos0])
    end.



-spec fmt_datetime(calendar:datetime()) -> string().
fmt_datetime({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    lists:flatten(io_lib:format("~w~2..0w~2..0w~2..0w~2..0w~2..0wZ",
				[Year, Month, Day, Hour, Minute, Second])).

-doc """
Encrypt `Data` to `Recipients`
""".
-spec encrypt(Data :: binary(),
	      Recipients :: [Certificate :: public_key:der_encoded()]) ->
	  {ok, Encrypted :: binary()} | {error, _}.
encrypt(Data, Recipients) ->
    encrypt(Data, Recipients, #{ digest_type => sha256, cipher => aes_256_cbc }).

-doc """
Encrypt `Data` to `Recipients`
""".
-spec encrypt(Data :: binary(),
	      Recipients :: [Certificate :: public_key:der_encoded()],
	      Opts :: #{ digest_type => crypto:sha2(),
			 auth_attrs => [#{ attrType := tuple(),
					   attrValues := [binary()] }],
			 cipher =>  aes_128_ofb |  aes_192_ofb |  aes_256_ofb |
			 aes_128_cfb128 | aes_192_cfb128 |  aes_256_cfb128 |
			 aes_128_cbc |  aes_192_cbc | aes_256_cbc |
			 aes_128_gcm | aes_192_gcm | aes_256_gcm }) ->
	  {ok, Encrypted :: binary()} | {error, _}.
encrypt(Data, Recipients, Opts0) ->
    Opts = maps:merge(#{ digest_type=> sha256,
			 cipher => aes_256_cbc }, Opts0),
    encrypt1(Data, Recipients, Opts).

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
    RecipientInfos = [ kari_or_ktri(CEK, KeyLength, DigestType, Cert) ||
			 Cert <- Recipients ],
    {ok, Parameters} =
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
    {ok, AuthEnvelopedDataDER} = 'CMS':encode('AuthEnvelopedData', AuthEnvelopedData),
    'CMS':encode('ContentInfo', #{ contentType => 'CMS':'id-ct-authEnvelopedData'(),
				   content => AuthEnvelopedDataDER });
encrypt1(Data, Recipients, #{ cipher := Cipher, digest_type := DigestType }) ->
    #{ key_length := KeyLength, block_size := BlockSize, iv_length := IvLength } =
	crypto:cipher_info(Cipher),
    <<CEK:KeyLength/binary, IV:IvLength/binary>> =
	crypto:strong_rand_bytes(KeyLength + IvLength),
    EncryptedContent =
	crypto:crypto_one_time(Cipher, CEK, IV, pad(Data, BlockSize), true),
    RecipientInfos = [ kari_or_ktri(CEK, KeyLength, DigestType, Cert)  ||
			 Cert <- Recipients ],
    EnvelopedData =
	#{ version => v2,
	   recipientInfos => RecipientInfos,
	   encryptedContentInfo =>
	       #{ contentType => 'CMS':'id-data'(),
		  contentEncryptionAlgorithm =>
		      #{ algorithm => oid(Cipher),
			 parameters => <<4, IvLength, IV/binary>>},
		  encryptedContent => EncryptedContent } },
    {ok, EnvelopedDataDER} = 'CMS':encode('EnvelopedData', EnvelopedData),
    'CMS':encode('ContentInfo', #{ contentType => 'CMS':'id-envelopedData'(),
				   content => EnvelopedDataDER}).

kari_or_ktri(CEK, KeyLength, DigestType, Cert) ->
    case cert_public_key(Cert) of
	#'RSAPublicKey'{} = RsaPub ->
	    ktri(CEK, DigestType, RsaPub, cert_ias_and_ski(Cert));
	{#'ECPoint'{}, _} = EcPub ->
	    kari(CEK, DigestType, EcPub, cert_ias_and_ski(Cert), KeyLength)
    end.

ktri(CEK, DigestType, RsaPub, {IaS, SkI}) ->
    {RId, Version} = case SkI of {_, false} -> {IaS, v0}; _ -> {SkI, v2} end,
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
    {ktri,
     #{ version => Version,
	keyEncryptionAlgorithm => #{ algorithm => ?'id-RSAES-OAEP',
				     parameters => KeyEncryptionParametersDER },
	rid => RId,
	encryptedKey => EncryptedKey }}.

kari(CEK, DigestType, {EcPub, EcParameters}, {IaS, SkI}, KeyLength) ->
    RId = case SkI of
	      {_, false} -> IaS;
	      {_, Id} -> {rKeyId, #{ subjectKeyIdentifier => Id }} end,
    Algorithm = case DigestType of
		    sha224 -> 'CMS':'dhSinglePass-stdDH-sha224kdf-scheme'();
		    sha256 -> 'CMS':'dhSinglePass-stdDH-sha256kdf-scheme'();
		    sha384 -> 'CMS':'dhSinglePass-stdDH-sha384kdf-scheme'();
		    sha512 -> 'CMS':'dhSinglePass-stdDH-sha512kdf-scheme'()
		end,
    Parameters =
	case KeyLength of
	    32 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 45>>; % aes256-wrap
	    24 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 25>>; % aes192-wrap
	    16 -> <<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 5>>   % aes128-wrap
	end,
    Ukm = crypto:strong_rand_bytes(42),
    {ok, SharedInfo} = shared_info_der(bin2oid(Parameters), Ukm, KeyLength),
    #'ECPrivateKey'{ publicKey = OriginatorKey } = EcPriv =
	public_key:generate_key(EcParameters),
    Z = public_key:compute_key(EcPub, EcPriv),
    KEK = x963_kdf(DigestType, Z, SharedInfo, KeyLength),
    RecipientEncryptedKeys =
	[#{ encryptedKey => rfc3394:wrap(CEK, KEK), rid => RId }],
    {kari,
     #{ version => v3,
	originator =>
	    {originatorKey,
	     #{ algorithm => #{ algorithm => ?'id-ecPublicKey' },
		publicKey => OriginatorKey }},
	ukm => Ukm,
	keyEncryptionAlgorithm =>
	    #{ algorithm => Algorithm, parameters => Parameters },
	recipientEncryptedKeys => RecipientEncryptedKeys }}.

-doc """
Decrypt CMS binary
""".
-spec decrypt(Encrypted :: binary(), RecipientCert :: public_key:der_encoded(),
	      RecipientKey :: public_key:der_encoded()) ->
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

decrypt_envl(Content, RecipientCertDER, RecipientKeyDER) ->
    IdData = 'CMS':'id-data'(),
    maybe
	{ok, #{ %% version := Version,
		recipientInfos := RecipientInfos,
		encryptedContentInfo :=
		    #{ contentType := IdData,
		       contentEncryptionAlgorithm :=
			   #{ algorithm := Algorithm,
			      parameters := <<4, 16, IV/binary>> },
		       encryptedContent := EncryptedContent }}} ?=
	    'CMS':decode('EnvelopedData', Content),
	Cipher = oid(Algorithm),
	#{ key_length := KeyLength, block_size := BlockSize } =
	    crypto:cipher_info(Cipher),
	{ok, CEK} ?= cek(RecipientInfos, RecipientCertDER,
			 RecipientKeyDER, KeyLength),
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
	{ok, CEK} = cek(RecipientInfos, RecipientCertDER, RecipientKeyDER, KeyLength),
	{ok, AAD} =
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

cek(RecipientInfos, RecipientCertDER, RecipientKeyDER, KeyLength) ->
    {IaS, SkI} = cert_ias_and_ski(RecipientCertDER),
    RecipientKey = public_key:der_decode('PrivateKeyInfo', RecipientKeyDER),
    case from_kari_or_ktri(IaS, SkI, RecipientInfos) of
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
	{error, _} = E -> E
    end.

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
    maybe
	{ok, DigestType} ?= case KeyEncryptionAlgorithm of
				DhSinglePassStdDHSha224kdfScheme -> {ok, sha224};
				DhSinglePassStdDHSha256kdfScheme -> {ok, sha256};
				DhSinglePassStdDHSha384kdfScheme -> {ok, sha384};
				DhSinglePassStdDHSha512kdfScheme -> {ok, sha512};
				_ -> {error, unsupported_key_encryption}
			    end,
	{ok, SharedInfo} ?= shared_info_der(bin2oid(KeyEncryptionParameters),
					    Ukm, KeyLength),
	Z = public_key:compute_key(#'ECPoint'{point = OriginatorKey}, RecipientKey),
	KEK = x963_kdf(DigestType, Z, SharedInfo, KeyLength),
	try
	    {ok, rfc3394:unwrap(EncryptedKey, KEK)}
	catch {error, iv_mismatch} = E0 -> E0 end
    else {error, _} = E1 -> E1 end.

from_kari_or_ktri(_, _, []) -> {error, no_matching_kari};
from_kari_or_ktri(IssuerAndSerialNumber, _KeyId,
		  [{ktri,
		    #{ version := v0,
		       keyEncryptionAlgorithm :=
			   #{ algorithm := KeyEncryptionAlgorithm,
			      parameters := KeyEncryptionParameters },
		       encryptedKey := EncryptedKey,
		       rid := IssuerAndSerialNumber
		     } } | _]) ->
    {ok, {KeyEncryptionAlgorithm, KeyEncryptionParameters, EncryptedKey}};
from_kari_or_ktri(_IssuerAndSerialNumber, SkI,
		  [{ktri,
		    #{ version := v2,
		       keyEncryptionAlgorithm :=
			   #{ algorithm := KeyEncryptionAlgorithm,
			      parameters := KeyEncryptionParameters },
		       encryptedKey := EncryptedKey,
		       rid := SkI
		     } } | _]) ->
    {ok, {KeyEncryptionAlgorithm, KeyEncryptionParameters, EncryptedKey}};
from_kari_or_ktri(IssuerAndSerialNumber, SkI, [{ktri, _} | T]) ->
    from_kari_or_ktri(IssuerAndSerialNumber, SkI, T);
from_kari_or_ktri(IssuerAndSerialNumber, {_, KeyId} = SkI,
		  [{kari,
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
		     } = Kari} | T]) ->
    Ukm = case maps:is_key(ukm, Kari) of
	      false -> false;
	      true -> maps:get(ukm, Kari) end,
    case lists:search(
	   fun(#{ rid := {rKeyId, #{ subjectKeyIdentifier := Id }} }) ->
		   Id =:= KeyId;
	      (#{ rid := IaS }) -> IaS =:= IssuerAndSerialNumber end,
	   RecipientEncryptedKeys) of
	false ->  from_kari_or_ktri(IssuerAndSerialNumber, SkI, T);
	{value, #{ encryptedKey := EncryptedKey } } ->
	    {ok, {OriginatorKey, Ukm, KeyEncryptionAlgorithm,
		  KeyEncryptionParameters, EncryptedKey}}
    end.

-doc """
Verify CMS DER binary `InDER`
""".
-spec verify(InDER :: public_key:der_encoded(),
	     Trusted :: [Certificate :: public_key:der_encoded()]) ->
	  {ok, EContent :: binary()} | {error, verify}.
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
	Validated = chain_validate(Included, Trusted),
	[_ | _] = L ?=
	    lists:filtermap(
	      fun(Cert) ->
		      {IaS, SkI} = cert_ias_and_ski(Cert),
		      PublicKey = cert_public_key(Cert),
		      case lists:search(
			     fun(#{ sid := Sid }) ->
				     Sid =:= IaS orelse Sid =:= SkI end,
			     SignerInfos) of
			  false -> false;
			  {value, Si} -> {true, {Si, PublicKey}} end
	      end, Trusted ++ Validated),

	true ?=
	    lists:any(
	      fun({#{ digestAlgorithm := #{ algorithm := DigestAlgOID },
		      signatureAlgorithm := SignatureAlgorithm,
		      signature := Signature } = SignerInfo,
		   Key}) ->
		      maybe
			  {ok, Opts} = pk_verify_opts(SignatureAlgorithm),
			  DigestType = oid(DigestAlgOID),
			  {ok, Digest} ?= digest(SignerInfo, DigestType, EContent),
			  public_key:verify({digest, Digest}, DigestType,
					    Signature, Key, Opts)
		      else _ -> false end end, L),
	{ok, EContent}
    else _ -> {error, verify} end.

included_certificates(#{ certificates := [_ | _] = Certs }) ->
    L0 = ['PKIX1Explicit88':encode('Certificate', C) || {certificate, C} <- Certs],
    {_, L} = lists:unzip(L0),
    lists:usort(L);
included_certificates(_) -> [].

pk_verify_opts(#{ algorithm := ?'id-RSASSA-PSS', parameters := Parameters}) ->
    maybe
	{ok, #{ maskGenAlgorithm := #{ algorithm := ?'id-mgf1',
				       parameters := MgParameters},
		saltLength := SaltLength}} ?=
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

cert_ias_and_ski(Cert) ->
    {ok, #{ tbsCertificate := TbsCertificate }}
	= 'PKIX1Explicit88':decode('Certificate', Cert),
    IaS = maps:with([serialNumber, issuer], TbsCertificate),
    SkI = subject_key_identifier(TbsCertificate),
    {{issuerAndSerialNumber, IaS}, {subjectKeyIdentifier, SkI}}.

subject_key_identifier(#{ extensions := Extensions }) ->
    case
	lists:search(fun(#{ extnID := ExtnId }) ->
			     ExtnId == 'CMS':'id-ce-subjectKeyIdentifier'() end,
		     Extensions) of
	false -> false;
	{value, #{ extnValue := ExtnValue }} ->
	    {ok, SubjectKeyIdentifier} =
		'CMS':decode('SubjectKeyIdentifier', ExtnValue),
	    SubjectKeyIdentifier end;
subject_key_identifier(#{}) -> false.

cert_public_key(Cert) ->
    #'OTPCertificate'{
       tbsCertificate =
	   #'OTPTBSCertificate'{
	      subjectPublicKeyInfo =
		  #'OTPSubjectPublicKeyInfo'{
		     algorithm =
			 #'PublicKeyAlgorithm'{parameters = Parameters},
		     subjectPublicKey = PubKey} } } =
	public_key:pkix_decode_cert(Cert, otp),
    cert_public_key1(PubKey, Parameters).

cert_public_key1(#'RSAPublicKey'{} = PubKey, _) -> PubKey;
cert_public_key1(PubKey, {params, #'Dss-Parms'{} = Parameters}) -> {PubKey, Parameters};
cert_public_key1(#'ECPoint'{} = PubKey, Parameters) -> {PubKey, Parameters}.

%% return all certs in `Included` that can where chain-validated
%% against certs in `Trusted` using intermediate certs from
%% `Included`
-spec chain_validate(Included :: [public_key:der_encoded()],
		     Trusted :: [public_key:der_encoded()]) ->
	  Valid :: [public_key:der_encoded()].
chain_validate(Included, Trusted) ->
    lists:filtermap(
      fun([C | _] = Chain) ->
	      maybe
		  [T] ?= [V || V <- Trusted,
			       public_key:pkix_is_issuer(C, V)],
		  {ok, _} ?= public_key:pkix_path_validation(T, Chain, []),
		  {true, lists:last(Chain)}
	      else _ -> false end end,
      [build_chain([C], Included -- [C]) || C <- Included]).

build_chain([Cert | _] = Chain, Certs) ->
    case lists:filter(
	   fun(C) -> public_key:pkix_is_issuer(Cert, C) end, Certs) of
	[] -> Chain;
	[IM] -> build_chain([IM | Chain], Certs -- [IM]) end.

x963_kdf(Hash, Key, Info, Length) ->
    #{ size := Size } = crypto:hash_info(Hash),
    Bin = << <<(crypto:hash(Hash, <<Key/binary, I:32, Info/binary>>))/binary >>
	     || I <- lists:seq(1, ceil(Length / Size)) >>,
    binary:part(Bin, 0, Length).

shared_info_der(WrapAlg, Ukm, KeyLength) ->
    SharedInfo0 = #{ keyInfo => #{ algorithm => WrapAlg },
		     suppPubInfo => <<(KeyLength * 8):32>> },
    SharedInfo  = case Ukm of
		      false -> SharedInfo0;
		      V -> SharedInfo0#{ entityUInfo => V } end,
    'CMS':encode('ECC-CMS-SharedInfo', SharedInfo).

pad(Data, 1) -> Data;
pad(Data, N) ->
    Pad = N - (erlang:byte_size(Data) rem N),
    <<Data/binary, (binary:copy(<<Pad>>, Pad))/binary>>.

unpad(Data, 1) -> Data;
unpad(Data, N) ->
    SLen = ((erlang:byte_size(Data) div N) - 1) * N,
    <<S:SLen/binary, E/binary>> = Data,
    <<_:15/binary, Pad>> = E,
    RLen = N - Pad,
    <<R:RLen/binary, _/binary>> = E,
    <<S/binary, R/binary>>.

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

bin2oid(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 45>>) -> ?'id-aes256-wrap';
bin2oid(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 25>>) -> ?'id-aes192-wrap';
bin2oid(<<48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 5>>) -> ?'id-aes128-wrap'.

-define('id-dsa-with-sha512', {2, 16, 840, 1, 101, 3, 4, 3, 4}).
-define('id-dsa-with-sha384', {2, 16, 840, 1, 101, 3, 4, 3, 3}).

sign_algs(H, K) -> { #{ algorithm => oid(H) }, sign_algs1(H, K) }.

sign_algs1(sha512, #'DSAPrivateKey'{}) -> #{ algorithm => ?'id-dsa-with-sha512' };
sign_algs1(sha384, #'DSAPrivateKey'{}) -> #{ algorithm => ?'id-dsa-with-sha384' };
sign_algs1(sha256, #'DSAPrivateKey'{}) -> #{ algorithm => ?'id-dsa-with-sha256' };
sign_algs1(sha224, #'DSAPrivateKey'{}) -> #{ algorithm => ?'id-dsa-with-sha224' };
sign_algs1(sha512, #'ECPrivateKey'{}) -> #{ algorithm => ?'ecdsa-with-SHA512' };
sign_algs1(sha384, #'ECPrivateKey'{}) -> #{ algorithm => ?'ecdsa-with-SHA384' };
sign_algs1(sha256, #'ECPrivateKey'{}) -> #{ algorithm => ?'ecdsa-with-SHA256' };
sign_algs1(sha224, #'ECPrivateKey'{}) -> #{ algorithm => ?'ecdsa-with-SHA224' };
sign_algs1(_, #'RSAPrivateKey'{}) ->
    #{ algorithm => ?'rsaEncryption', parameters => <<5, 0>> }.
