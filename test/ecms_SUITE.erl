-module(ecms_SUITE).

-export([all/0]).

-export([verify/1, verify_noattr/1, verify_nocerts/1, verify_chain/1, verify_fail/1]).

-export([sign/1, sign_chain/1, sign_fail/1]).

-export([decrypt_ec/1, decrypt_rsa/1, decrypt_keyid/1]).

-export([encrypt/1]).


all() ->
    [verify, verify_noattr, verify_nocerts, verify_chain, verify_fail,
     sign, sign_chain, sign_fail,
     decrypt_ec, decrypt_rsa, decrypt_keyid,
     encrypt
    ].

encrypt(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [SelfS0, Rsa1] = [filename:join(DataD, V) || V <- ["selfs0.pem", "smrsa1.pem"]],
    [PlainF, EncryptedF] =
	[filename:join(PrivD, V) || V <- ["plain", "encrypted"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    L = [{C, H} || C <- [aes_128_ofb, aes_192_ofb, aes_256_ofb,
			 aes_128_cfb128, aes_192_cfb128, aes_256_cfb128,
			 aes_128_cbc, aes_192_cbc, aes_256_cbc,
			 aes_128_gcm, aes_192_gcm, aes_256_gcm],
		   H <- [sha224, sha256, sha384, sha512]],
    lists:foreach(
      fun({C, H}) ->
	      {ok, Enrypted} = ecms:encrypt(Plain, [der_cert_of_pem(SelfS0),
						    der_cert_of_pem(Rsa1)],
					    #{ cipher => C, digest_type => H }),
	      {ok, Plain} = ecms:decrypt(Enrypted, der_cert_of_pem(SelfS0),
					 der_key_of_pem(SelfS0)),
	      {ok, Plain} = ecms:decrypt(Enrypted, der_cert_of_pem(Rsa1),
					 der_key_of_pem(Rsa1)),
	      ok = file:write_file(EncryptedF, Enrypted),
	      cms_decrypt(EncryptedF, PlainF, SelfS0),
	      {ok, Plain} = file:read_file(PlainF),
	      cms_decrypt(EncryptedF, PlainF, Rsa1),
	      {ok, Plain} = file:read_file(PlainF)
      end, L).

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
		  ecms:decrypt(Encrypted, der_cert_of_pem(Rsa1),
			       der_key_of_pem(Rsa1)) end,
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
	      {ok, Plain} = ecms:decrypt(Encrypted, der_cert_of_pem(SelfS0),
					 der_key_of_pem(SelfS0)) end,
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
		  ecms:decrypt(Encrypted, der_cert_of_pem(Recipient),
			       der_key_of_pem(Recipient))
      end, Recipients).

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
				signers => [der_cert_and_key_of_pem(Dsa1),
					    der_cert_and_key_of_pem(Ec1)] }),
    ok = file:write_file(SignedF, Signed),
    cms_verify(SignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Plain} = file:read_file(PlainF),
    Signers = lists:map(fun der_cert_and_key_of_pem/1, [Dsa2, Ec2, Rsa2, Rsa1]),
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
    {ok, Signed3} = ecms:sign(Plain, der_cert_of_pem(SelfS0), der_key_of_pem(SelfS0)),
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
				       included_certs => [der_cert_of_pem(Im0)],
				       signers => [der_cert_and_key_of_pem(Leaf0)]
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
    {ok, Plain} = ecms:verify(Signed, [der_cert_of_pem(SmRoot)]),
    {error, verify} = ecms:verify(Signed, [der_cert_of_pem(Rsa2)]),
    cms_resign(SignedF, ResignedF, ["-md", "sha224",
				    "-signer", Dsa2, "-signer", Ec2,
				    "-signer", Rsa2, "-signer", Rsa1]),
    cms_verify(ResignedF, PlainF, ["-CAfile", SmRoot]),
    {ok, Resigned} = file:read_file(ResignedF),
    {ok, Plain} = ecms:verify(Resigned, [der_cert_of_pem(Rsa2)]).

verify_noattr(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],

    [SelfS0] = [filename:join(DataD, V) || V <- ["selfs0.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha256", "-keyid", "-signer", SelfS0, "-noattr"]),
    cms_verify(SignedF, PlainF, ["-CAfile", SelfS0]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [der_cert_of_pem(SelfS0)]).

verify_nocerts(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],

    [SelfS3] = [filename:join(DataD, V) || V <- ["selfs3.pem"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha256", "-signer", SelfS3, "-nocerts"]),
    cms_verify(SignedF, PlainF, ["-CAfile", SelfS3, "-certfile", SelfS3]),
    {ok, Signed} = file:read_file(SignedF),
    {ok, Plain} = ecms:verify(Signed, [der_cert_of_pem(SelfS3)]).

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
    {ok, Plain} = ecms:verify(Signed, [der_cert_of_pem(Policy0)]).

verify_fail(Config) ->
    [PrivD, DataD] = [proplists:get_value(V, Config) || V <- [priv_dir, data_dir]],
    [PlainF, SignedF] = [filename:join(PrivD, V) || V <- ["plain", "signed"]],
    [Leaf0, Im0, Policy0, Policy1, SpecialF, Selfsigned, ManipulatedContentF] =
	[filename:join(DataD, V) ||
	    V <- ["leaf0.pem", "0Im.pem", "0Policy.pem", "1Policy.pem",
		  "selfsigned_special.c", "selfsigned.c", "manipulated_content"]],
    Plain = testinput(),
    ok = file:write_file(PlainF, Plain),
    cms_sign(PlainF, SignedF, ["-md", "sha512", "-keyid", "-signer", Leaf0,
			       "-certfile", Im0]),
    cms_verify(SignedF, PlainF, ["-CAfile", Policy0]),
    {ok, Signed} = file:read_file(SignedF),
    {error, verify} = ecms:verify(Signed, [der_cert_of_pem(SpecialF),
					   der_cert_of_pem(Policy1)]),
    {ok, ManipulatedContent} = file:read_file(ManipulatedContentF),
    {error, verify} = ecms:verify(ManipulatedContent,
				  [der_cert_of_pem(Selfsigned)]).


testinput() -> <<"fooobar">>.


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
    Opts = [stream, in, eof, hide, stderr_to_stdout, exit_status, {arg0, Arg0}, {args, Args}],
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

der_cert_and_key_of_pem(PemFile) ->
    {der_cert_of_pem(PemFile), der_key_of_pem(PemFile)}.

der_key_of_pem(PemFile) -> der_of_pem('PrivateKeyInfo', PemFile).
der_cert_of_pem(PemFile) -> der_of_pem('Certificate', PemFile).

der_of_pem(K, PemFile) ->
    {ok, Pem} = file:read_file(PemFile),
    {K, DER, not_encrypted} = lists:keyfind(K, 1, public_key:pem_decode(Pem)),
    DER.

supported_ciphers_and_hashes() ->
    [{"-aes-" ++ integer_to_list(KS) ++ "-" ++ atom_to_list(M),
      atom_to_list(H)} ||
	KS <- [128, 192, 256],
	M <- [ofb, cbc, gcm, cfb],
	H <- [sha224, sha256, sha384, sha512]].
