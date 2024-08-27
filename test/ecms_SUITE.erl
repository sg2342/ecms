-module(ecms_SUITE).

-export([all/0]).

-export([verify/1, verify_noattr/1, verify_nocerts/1, verify_chain/1, verify_fail/1]).

all() ->
    [verify, verify_noattr, verify_nocerts, verify_chain, verify_fail].


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

der_cert_of_pem(PemFile) -> der_of_pem('Certificate', PemFile).

der_of_pem(K, PemFile) ->
    {ok, Pem} = file:read_file(PemFile),
    {K, DER, not_encrypted} = lists:keyfind(K, 1, public_key:pem_decode(Pem)),
    DER.
