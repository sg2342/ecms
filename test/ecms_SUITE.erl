-module(ecms_SUITE).

-export([all/0]).

-export([verify/1, verify_noattr/1, verify_nocerts/1, verify_chain/1,
	 verify_pss/1, verify_fail/1]).

-export([sign/1, sign_chain/1, sign_fail/1]).

-export([decrypt_ec/1, decrypt_rsa/1, decrypt_keyid/1, decrypt_fail/1]).

-export([encrypt/1, encrypt_auth_attrs/1, encrypt_fail/1]).

-export([curves/1]).

all() ->
    [verify, verify_noattr, verify_nocerts, verify_chain, verify_fail,
     verify_pss, sign, sign_chain, sign_fail, decrypt_ec, decrypt_rsa,
     decrypt_keyid, decrypt_fail, encrypt, encrypt_auth_attrs,
     encrypt_fail, curves].

encrypt(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [SelfS0, SelfS3, SelfS4, Rsa1] =
	[filename:join(DataD, V) ||
	    V <- ["selfs0.pem", "selfs3.pem", "selfs4.pem", "smrsa1.pem"]],
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    CertsWithoutSkI = [SelfS3, SelfS4],
    lists:foreach(
      fun(Cert) ->
	      {ok, Encrypted} = ecms:encrypt(Plain, [cert_from_pemf(Cert)]),
	      {ok, Plain} = ecms:decrypt(Encrypted, cert_from_pemf(Cert),
					 key_from_pemf(Cert)),
	      ok = file:write_file(EncryptedF, Encrypted),
	      cms_decrypt(EncryptedF, PlainF, Cert),
	      {ok, Plain} = file:read_file(PlainF)
      end, CertsWithoutSkI),

    Algs = [{C, H} || C <- [aes_128_ofb, aes_192_ofb, aes_256_ofb,
			    aes_128_cfb128, aes_192_cfb128, aes_256_cfb128,
			    aes_128_cbc, aes_192_cbc, aes_256_cbc,
			    aes_128_gcm, aes_192_gcm, aes_256_gcm],
		      H <- [sha224, sha256, sha384, sha512]],
    lists:foreach(
      fun({C, H}) ->
	      {ok, Enrypted} = ecms:encrypt(Plain, [cert_from_pemf(SelfS0),
						    cert_from_pemf(Rsa1)],
					    #{ cipher => C, digest_type => H }),
	      {ok, Plain} = ecms:decrypt(Enrypted, cert_from_pemf(SelfS0),
					 key_from_pemf(SelfS0)),
	      {ok, Plain} = ecms:decrypt(Enrypted, cert_from_pemf(Rsa1),
					 key_from_pemf(Rsa1)),
	      ok = file:write_file(EncryptedF, Enrypted),
	      cms_decrypt(EncryptedF, PlainF, SelfS0),
	      {ok, Plain} = file:read_file(PlainF),
	      cms_decrypt(EncryptedF, PlainF, Rsa1),
	      {ok, Plain} = file:read_file(PlainF)
      end, Algs).

encrypt_auth_attrs(Config) ->
    [_PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [SelfS0] = [filename:join(DataD, V) || V <- ["selfs0.pem"]],
    Plain = testinput(),
    AuthAttrs =
	[ #{ attrType => 'CMS':'id-signingTime'(),
	     attrValues => [<<24, 15, 49, 57, 55, 48, 48, 49, 48, 49, 48, 48,
			      48, 48, 48, 48, 90>>] } ],
    {ok, Encrypted} = ecms:encrypt(Plain, [cert_from_pemf(SelfS0)],
				   #{ cipher => aes_192_gcm,
				      auth_attrs => AuthAttrs }),
%%% OpenSSL CMS fails with nested asn1 error
%%%    [PlainF, EncryptedF] =
%%%	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
%%%    ok = file:write_file(EncryptedF, Encrypted),
%%%    cms_decrypt(EncryptedF, PlainF, SelfS0),
%%%    {ok, Plain} = file:read_file(PlainF),
    {ok, Plain} = ecms:decrypt(Encrypted, cert_from_pemf(SelfS0),
			       key_from_pemf(SelfS0)).

encrypt_fail(Config) ->
    Dsa1 = filename:join(proplists:get_value(data_dir, Config), "smdsa1.pem"),
    {error, unsupported_key_type} =
	ecms:encrypt(<<>>, [cert_from_pemf(Dsa1)]),
    {error, der_decode_cert} =
	ecms:encrypt(<<>>, [<<>>], #{cipher => aes_256_gcm}),
    {error, der_decode_cert} = ecms:encrypt(<<>>, [<<>>]).

decrypt_rsa(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    Rsa1 = filename:join(DataD, "smrsa1.pem"),
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    lists:foreach(
      fun({Cipher, Hash}) ->
	      cms_encrypt(PlainF, EncryptedF,
			  [Cipher, "-recip", Rsa1,
			   "-keyopt", "rsa_padding_mode:oaep",
			   "-keyopt", "rsa_oaep_md:" ++ Hash]),
	      {ok, Encrypted} = file:read_file(EncryptedF),
	      cms_decrypt(EncryptedF, PlainF, Rsa1),
	      {ok, Plain} = file:read_file(PlainF),
	      {ok, Plain} =
		  ecms:decrypt(Encrypted, cert_from_pemf(Rsa1),
			       key_from_pemf(Rsa1)) end,
      supported_ciphers_and_hashes()).

decrypt_ec(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    SelfS0 = filename:join(DataD, "selfs0.pem"),
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    lists:foreach(
      fun({Cipher, Hash}) ->
	      cms_encrypt(PlainF, EncryptedF,
			  [Cipher, "-recip", SelfS0,
			   "-keyopt", "ecdh_kdf_md:" ++ Hash]),
	      {ok, Encrypted} = file:read_file(EncryptedF),
	      {ok, Plain} = ecms:decrypt(Encrypted, cert_from_pemf(SelfS0),
					 key_from_pemf(SelfS0)) end,
      supported_ciphers_and_hashes()).

decrypt_keyid(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [SelfS0, SelfS1, Rsa1, Rsa2] = Recipients =
	[filename:join(DataD, V) ||
	    V <- ["selfs0.pem", "selfs1.pem", "smrsa1.pem", "smrsa2.pem"]],
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_encrypt(PlainF, EncryptedF,
		["-aes-256-gcm", "-recip", SelfS0, "-keyopt", "ecdh_kdf_md:sha224",
		 "-recip", SelfS1, "-keyopt", "ecdh_kdf_md:sha384",
		 "-recip", Rsa1,
		 "-recip", Rsa2, "-keyopt", "rsa_padding_mode:oaep",
		 "-keyopt", "rsa_oaep_md:sha512", "-keyid"]),
    {ok, Encrypted} = file:read_file(EncryptedF),
    lists:foreach(
      fun(Recipient) ->
	      cms_decrypt(EncryptedF, PlainF, Recipient),
	      {ok, Plain} = file:read_file(PlainF),
	      {ok, Plain} =
		  ecms:decrypt(Encrypted, cert_from_pemf(Recipient),
			       key_from_pemf(Recipient))
      end, Recipients).

decrypt_fail(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [SelfS0, Rsa1, IvMismatchF, IvMismatchAeadF, AeadFailedF, InvalidOaepF] =
	[filename:join(DataD, V) ||
	    V <- ["selfs0.pem", "smrsa1.pem", "iv_mismatch", "iv_mismatch_aead",
		  "aead_decrypt_failed", "invalid_oaep"]],
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_encrypt(PlainF, EncryptedF, ["-aes256", "-recip", SelfS0,
				     "-keyopt", "ecdh_kdf_md:sha1"]),
    cms_decrypt(EncryptedF, PlainF, SelfS0),
    {ok, Encrypted} = file:read_file(EncryptedF),
    {error, unsupported_key_encryption} =
	ecms:decrypt(Encrypted, cert_from_pemf(SelfS0), key_from_pemf(SelfS0)),
    {error, no_matching_kari_or_ktri} =
	ecms:decrypt(Encrypted, cert_from_pemf(Rsa1), key_from_pemf(Rsa1)),
    {ok, IvMismatch} = file:read_file(IvMismatchF),
    {error, iv_mismatch} =
	ecms:decrypt(IvMismatch, cert_from_pemf(SelfS0), key_from_pemf(SelfS0)),
    {ok, IvMismatchAead} = file:read_file(IvMismatchAeadF),
    {error, iv_mismatch} =
	ecms:decrypt(IvMismatchAead, cert_from_pemf(SelfS0), key_from_pemf(SelfS0)),
    {ok, AeadFailed} = file:read_file(AeadFailedF),
    {error, aead_decrypt_failed} =
	ecms:decrypt(AeadFailed, cert_from_pemf(SelfS0), key_from_pemf(SelfS0)),
    {ok, InvalidOaep} = file:read_file(InvalidOaepF),
    {error, {asn1, _}} =
	ecms:decrypt(InvalidOaep, cert_from_pemf(Rsa1), key_from_pemf(Rsa1)),
    {error, der_decode_private_key} =
	ecms:decrypt(Encrypted, cert_from_pemf(Rsa1), <<>>),
    {error, {asn1, _}} = ecms:decrypt(<<>>, <<>>, <<>>).

sign(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF, ResignedF] =
	[filename:join(PrivD, V) || V <- ["plain", "signed", "resigned"]],
    [Dsa1, Dsa2, Ec1, Ec2, Rsa1, Rsa2, SelfS0, SmRoot] =
	[filename:join(DataD, V) ||
	    V <- ["smdsa1.pem", "smdsa2.pem", "smec1.pem", "smec2.pem",
		  "smrsa1.pem", "smrsa2.pem", "selfs0.pem", "smroot.pem"]],
    Plain = testinput(),
    {ok, Signed} = ecms:sign(Plain,
			     #{ digest_type => sha224,
				signers => [cert_key_from_pemf(Dsa1),
					    cert_key_from_pemf(Ec1)] }),
    ok = file:write_file(SignedF, Signed),
    cms_verify(SignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Plain} = file:read_file(PlainF),
    Signers = lists:map(fun cert_key_from_pemf/1, [Dsa2, Ec2, Rsa2, Rsa1]),
    {ok, Resigned} = ecms:sign(Signed,
			       #{ digest_type => sha224,
				  resign => true,
				  signers => Signers }),
    ok = file:write_file(ResignedF, Resigned),
    cms_verify(ResignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Plain} = file:read_file(PlainF),
    lists:foreach(
      fun(H) ->
	      {ok, Signed2} = ecms:sign(Plain,
					#{ digest_type => H,
					   signers => Signers }),
	      ok = file:write_file(SignedF, Signed2),
	      cms_verify(SignedF, PlainF, ["-CAfile", SmRoot]),
	      {ok, Plain} = file:read_file(PlainF)
      end, [sha512, sha256, sha384]),
    {ok, Signed3} = ecms:sign(Plain, cert_from_pemf(SelfS0), key_from_pemf(SelfS0)),
    ok = file:write_file(SignedF, Signed3),
    cms_verify(SignedF, PlainF, ["-CAfile", SelfS0]),
    {ok, Plain} = file:read_file(PlainF).

sign_chain(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],
    [Leaf0, Im0, Policy0] = [filename:join(DataD, V) ||
				V <- ["leaf0.pem", "0Im.pem", "0Policy.pem"]],
    Plain = testinput(),
    {ok, Signed} = ecms:sign(Plain, #{ digest_type => sha512,
				       included_certs => [cert_from_pemf(Im0)],
				       signers => [cert_key_from_pemf(Leaf0)]
				     }),
    ok = file:write_file(SignedF, Signed),
    cms_verify(SignedF, PlainF, ["-CAfile", Policy0]),
    {ok, Plain} = file:read_file(PlainF).

sign_fail(_Config) ->
    {error, _} = ecms:sign(<<>>, #{ signers => [{<<>>, <<>>}] }),
    {error, _} = ecms:sign(<<>>, #{ resign => true, signers => [{<<>>, <<>>}] }).

verify(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF, ResignedF] = [filename:join(PrivD, V) ||
				       V <- ["plain", "signed", "resigned"]],
    [Dsa1, Dsa2, Ec1, Ec2, Rsa1, Rsa2, SmRoot] =
	[filename:join(DataD, V) ||
	    V <- ["smdsa1.pem", "smdsa2.pem", "smec1.pem", "smec2.pem",
		  "smrsa1.pem", "smrsa2.pem", "smroot.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha224", "-signer", Dsa1, "-signer", Ec1]),
    cms_verify(SignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(SmRoot)]),
    {error, verify} = ecms:verify(Signed, [cert_from_pemf(Rsa2)]),
    cms_resign(SignedF, ResignedF, ["-md", "sha224",
				    "-signer", Dsa2, "-signer", Ec2,
				    "-signer", Rsa2, "-signer", Rsa1]),
    cms_verify(ResignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Resigned} = file:read_file(ResignedF),
    {ok, Plain} = ecms:verify(Resigned, [cert_from_pemf(Rsa2)]).

verify_noattr(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],

    [SelfS0] = [filename:join(DataD, V) || V <- ["selfs0.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha256", "-keyid", "-signer", SelfS0, "-noattr"]),
    cms_verify(SignedF, PlainF, ["-CAfile", SelfS0]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(SelfS0)]).

verify_nocerts(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],

    [SelfS0] = [filename:join(DataD, V) || V <- ["selfs0.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha256", "-signer", SelfS0, "-nocerts"]),
    cms_verify(SignedF, PlainF, ["-CAfile", SelfS0, "-certfile", SelfS0]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(SelfS0)]).

verify_chain(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],
    [Leaf0, Im0, Policy0] = [filename:join(DataD, V) ||
				V <- ["leaf0.pem", "0Im.pem", "0Policy.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha384", "-signer", Leaf0, "-certfile", Im0]),
    cms_verify(SignedF, PlainF, ["-CAfile", Policy0]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(Policy0)]).

verify_pss(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [Rsa1, SmRoot] = [filename:join(DataD, V) || V <- ["smrsa1.pem", "smroot.pem"]],
    [PlainF, SignedF] =
	[filename:join(PrivD, V) || V <- ["plain", "signed"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha256", "-signer", Rsa1,
			       "-keyopt", "rsa_padding_mode:pss",
			       "-keyopt", "rsa_pss_saltlen:24",
			       "-keyopt", "rsa_mgf1_md:sha224"]),
    {ok, Signed} = file:read_file(SignedF),
    cms_verify(SignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Plain} = file:read_file(PlainF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(SmRoot)]).

verify_fail(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],
    [Leaf0, Im0, Policy0, Policy1, SpecialF, Selfsigned,
     ManipulatedContentF, InvalidPssF, Rsa1] =
	[filename:join(DataD, V) ||
	    V <- ["leaf0.pem", "0Im.pem", "0Policy.pem", "1Policy.pem",
		  "selfsigned_special.c", "selfsigned.c", "manipulated_content",
		  "invalid_pss", "smrsa1.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha512", "-keyid", "-signer", Leaf0,
			       "-certfile", Im0]),
    cms_verify(SignedF, PlainF, ["-CAfile", Policy0]),
    {ok, Signed} = file:read_file(SignedF),
    {error, der_decode_cert} = ecms:verify(Signed, [<<>>]),
    {error, verify} = ecms:verify(Signed, [cert_from_pemf(SpecialF),
					   cert_from_pemf(Policy1)]),
    {ok, ManipulatedContent} = file:read_file(ManipulatedContentF),
    {error, verify} = ecms:verify(ManipulatedContent,
				  [cert_from_pemf(Selfsigned)]),
    {ok, InvalidPss} = file:read_file(InvalidPssF),
    {error, verify} = ecms:verify(InvalidPss, [cert_from_pemf(Rsa1)]).

curves(Config) ->
    PrivD = proplists:get_value(priv_dir, Config),
    [PlainF, SignedF, EncryptedF, CertF] =
	[filename:join(PrivD, V) ||
	    V <- ["plain", "signed", "encrypted", "cert"] ],
    lists:foreach(
      fun(Curve) ->
	      selfsigned(PrivD, Curve, CertF),
	      t_sign(PlainF, SignedF, CertF),
	      t_verify(PlainF, SignedF, CertF),
	      t_encrypt(PlainF, EncryptedF, CertF),
	      t_decrypt(PlainF, EncryptedF, CertF)
      end,
      [prime256v1, prime192v1,
       sect571r1, sect571k1, sect409r1, sect409k1, secp521r1, secp384r1,
       secp224r1, secp224k1, secp192k1, secp160r2, secp128r2, secp128r1,
       sect233r1, sect233k1, sect193r2, sect193r1, sect131r2, sect131r1,
       sect283r1, sect283k1, sect163r2, secp256k1, secp160k1, secp160r1,
       secp112r2, secp112r1, sect113r2, sect113r1, sect239k1, sect163r1,
       sect163k1, brainpoolP160r1, brainpoolP160t1,
       brainpoolP192r1, brainpoolP192t1, brainpoolP224r1, brainpoolP224t1,
       brainpoolP256r1, brainpoolP256t1, brainpoolP320r1, brainpoolP320t1,
       brainpoolP384r1, brainpoolP384t1, brainpoolP512r1, brainpoolP512t1]).

t_sign(PlainF, SignedF, CertF) ->
    Plain = testinput(),
    {ok, Signed} = ecms:sign(Plain, cert_from_pemf(CertF), key_from_pemf(CertF)),
    ok = file:write_file(SignedF, Signed),
    cms_verify(SignedF, PlainF, ["-CAfile", CertF]),
    {ok, Plain} = file:read_file(PlainF).

t_verify(PlainF, SignedF, CertF) ->
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha224", "-signer", CertF]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [cert_from_pemf(CertF)]).

t_encrypt(PlainF, EncryptedF, CertF) ->
    Plain = testinput(),
    {ok, Encrypted} = ecms:encrypt(Plain, [cert_from_pemf(CertF)]),
    ok = file:write_file(EncryptedF, Encrypted),
    cms_decrypt(EncryptedF, PlainF, CertF),
    {ok, Plain} = file:read_file(PlainF).

t_decrypt(PlainF, EncryptedF, CertF) ->
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_encrypt(PlainF, EncryptedF, ["-aes-256-cbc", "-recip", CertF, "-keyopt",
				     "ecdh_kdf_md:sha384"]),
    {ok, Encrypted} = file:read_file(EncryptedF),
    {ok, Plain} = ecms:decrypt(Encrypted, cert_from_pemf(CertF),
			       key_from_pemf(CertF)).

selfsigned(Dir, Curve, CertF) ->
    [K, C, R] = [ filename:join(Dir, V) || V <- ["k", "c", "r"] ],
    GenPKey = ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
	       "ec_param_enc:named_curve",
	       "-pkeyopt", "ec_paramgen_curve:" ++ atom_to_list(Curve),
	       "-out", K],
    Req = ["openssl", "req", "-new", "-out", R, "-key", K, "-subj",
	   "/CN=" ++ atom_to_list(Curve)],
    X509 = ["openssl", "x509", "-req", "-in", R, "-out", C, "-signkey", K],
    {0, _} = spwn(GenPKey),
    {0, _} = spwn(Req),
    {0, _} = spwn(X509),
    {ok, Cert} = file:read_file(C),
    {ok, Key} = file:read_file(K),
    ok = file:write_file(CertF, [Cert, Key]),
    [file:delete(V) || V <- [K, C, R]].

testinput() -> crypto:strong_rand_bytes(rand:uniform(321)).

cms_resign(Signed, Resigned, Tail) ->
    {0, _} = spwn(["openssl", "cms", "-resign", "-nodetach", "-nosmimecap",
		   "-binary", "-inform", "DER", "-in", Signed, "-outform", "DER",
		   "-out", Resigned | Tail]).

cms_sign(Plain, Signed, Tail) ->
    {0, _} = spwn(["openssl", "cms", "-sign", "-nodetach", "-nosmimecap",
		   "-binary", "-in", Plain, "-outform", "DER", "-out", Signed | Tail]).

cms_verify(Signed, Plain, Tail) ->
    {0, _} = spwn(["openssl", "cms", "-verify",
		   "-inform", "DER", "-in", Signed, "-out", Plain | Tail]).

cms_encrypt(Plain, Encrypted, Tail) ->
    {0, _} = spwn(["openssl", "cms", "-encrypt", "-binary", "-in", Plain,
		   "-outform", "DER", "-out", Encrypted | Tail]).

cms_decrypt(Encrypted, Plain, Recip) -> cms_decrypt(Encrypted, Plain, Recip, []).

cms_decrypt(Encrypted, Plain, Recip, Tail) ->
    {0, _} = spwn(["openssl", "cms", "-decrypt", "-inform", "DER",
		   "-in", Encrypted, "-out", Plain, "-recip", Recip | Tail]).

-spec spwn([string()]) -> {ExitCode :: integer(), string()}.
spwn([Arg0 | Args]) ->
    Opts = [stream, in, eof, hide, stderr_to_stdout, exit_status, {arg0, Arg0},
	    {args, Args}],
    spwn1(open_port({spawn_executable, os:find_executable(Arg0)}, Opts), []).

spwn1(Port, SoFar) ->
    receive
	{Port, {data, Bytes}} ->
	    spwn1(Port, [SoFar | Bytes]);
	{Port, eof} ->
	    Port ! {self(), close},
	    receive {Port, closed} -> true end,
	    receive {'EXIT', Port, _} -> ok after 1 -> ok end,
	    ExitCode = receive {Port, {exit_status, Code}} -> Code end,
	    {ExitCode, lists:flatten(SoFar)}
    end.

cert_key_from_pemf(PemFile) ->
    {cert_from_pemf(PemFile), key_from_pemf(PemFile)}.

key_from_pemf(PemFile) -> from_pemf('PrivateKeyInfo', PemFile).
cert_from_pemf(PemFile) -> from_pemf('Certificate', PemFile).

from_pemf(K, PemFile) ->
    {ok, Pem} = file:read_file(PemFile),
    {K, DER, not_encrypted} = lists:keyfind(K, 1, public_key:pem_decode(Pem)),
    DER.

supported_ciphers_and_hashes() ->
    [{"-aes-" ++ integer_to_list(KS) ++ "-" ++ atom_to_list(M),
      atom_to_list(H)} ||
	KS <- [128, 192, 256],
	M <- [ofb, cbc, gcm, cfb],
	H <- [sha224, sha256, sha384, sha512]].
