-module(ecms).
-moduledoc """
Implementation of (parts of) RFC 5652 Cryptographic Message Syntax (CMS)
""".

-export([verify/2]).

-include_lib("public_key/include/public_key.hrl").

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
