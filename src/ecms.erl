-module(ecms).
-moduledoc """
Implementation of (parts of) RFC 5652 Cryptographic Message Syntax (CMS)
""".

-export([verify/2, sign/2, sign/3]).

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
	{ok, #{contentType := IdSignedData, content := SignedDataDER}} ?=
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

	DigestAlgorithms = lists:usort([A || #{digestAlgorithm := A} <- SignerInfos]
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
	{ok, #{tbsCertificate := TbsCertificate}}
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


-define('id-dsa-with-sha512', {2, 16, 840, 1, 101, 3, 4, 3, 4}).
-define('id-dsa-with-sha384', {2, 16, 840, 1, 101, 3, 4, 3, 3}).

sign_algs(sha512 = H, K) -> { #{algorithm => ?'id-sha512'}, sign_algs1(H, K) };
sign_algs(sha384 = H, K) -> { #{algorithm => ?'id-sha384'}, sign_algs1(H, K) };
sign_algs(sha256 = H, K) -> { #{algorithm => ?'id-sha256'}, sign_algs1(H, K) };
sign_algs(sha224 = H, K) -> { #{algorithm => ?'id-sha224'}, sign_algs1(H, K) }.

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


-spec fmt_datetime(calendar:datetime()) -> string().
fmt_datetime({{Year, Month, Day}, {Hour, Minute, Second}}) ->
    lists:flatten(io_lib:format("~w~2..0w~2..0w~2..0w~2..0w~2..0wZ",
				[Year, Month, Day, Hour, Minute, Second])).

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
	{ok, #{contentType := IdSignedData, content := SignedDataDER}} ?=
	    'CMS':decode('ContentInfo', InDER),
	{ok, #{encapContentInfo := #{ eContentType := IdData,
				      eContent := EContent },
	       signerInfos := SignerInfos} = SignedData} ?=
	    'CMS':decode('SignedData', SignedDataDER),

	Included = included_certificates(SignedData),
	Validated = chain_validate(Included, Trusted),
	[_ | _] = L ?=
	    lists:filtermap(
	      fun(Cert) ->
		      {IaS, SkI} = cert_ias_and_ski(Cert),
		      PublicKey = cert_public_key(Cert),
		      case lists:search(
			     fun(#{sid := Sid}) -> Sid =:= IaS orelse Sid =:= SkI end,
			     SignerInfos) of
			  false -> false;
			  {value, Si} -> {true, {Si, PublicKey}} end
	      end, Trusted ++ Validated),

	true ?=
	    lists:any(
	      fun({#{digestAlgorithm := #{algorithm := DigestAlgOID},
		     signature := Signature} = SignerInfo,
		   Key}) ->
		      maybe
			  DigestType = digest_type(DigestAlgOID),
			  {ok, Digest} ?= digest(SignerInfo, DigestType, EContent),
			  public_key:verify({digest, Digest}, DigestType,
					    Signature, Key)
		      else _ -> false end end, L),
	{ok, EContent}
    else _ -> {error, verify} end.

included_certificates(#{certificates := [_ | _] = Certs}) ->
    L0 = ['PKIX1Explicit88':encode('Certificate', C) || {certificate, C} <- Certs],
    {_, L} = lists:unzip(L0),
    lists:usort(L);
included_certificates(_) -> [].

digest_type(?'id-sha512') -> sha512;
digest_type(?'id-sha384') -> sha384;
digest_type(?'id-sha256') -> sha256;
digest_type(?'id-sha224') -> sha224.

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
    {ok, #{tbsCertificate := TbsCertificate}}
	= 'PKIX1Explicit88':decode('Certificate', Cert),
    IaS = maps:with([serialNumber, issuer], TbsCertificate),
    SkI = subject_key_identifier(TbsCertificate),
    {{issuerAndSerialNumber, IaS}, {subjectKeyIdentifier, SkI}}.

subject_key_identifier(#{ extensions := Extensions }) ->
    case
	lists:search(fun(#{extnID := ExtnId}) ->
			     ExtnId == 'CMS':'id-ce-subjectKeyIdentifier'() end,
		     Extensions) of
	false -> false;
	{value, #{extnValue := ExtnValue}} ->
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
