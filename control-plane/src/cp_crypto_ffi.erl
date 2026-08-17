%% Thin FFI over OTP :crypto for ECDSA P-256 (DNSSEC algorithm 13).
%% :crypto speaks DER-encoded signatures; DNSSEC wants raw r||s (64 bytes,
%% RFC 6605 §4) — the conversion lives here, next to the calls that need it.
-module(cp_crypto_ffi).
-export([ec_generate/0, ecdsa_sign_raw/2, ecdsa_verify_raw/3,
         ecdsa_sign_der/2, ecdsa_verify_der/3, ed25519_verify/3,
         ed25519_verify_safe/3, ecdsa_verify_any_safe/3,
         ed25519_generate_public/0, self_signed_cert/7, cert_spki_and_san/1, cert_extension/2]).

-include_lib("public_key/include/public_key.hrl").

%% A fresh Ed25519 public key (32 bytes) — device keys are Ed25519 iroh
%% NodeIds, and seeded demo/test zones need real curve points because the
%% synchronicity client rejects undecodable nk= values.
ed25519_generate_public() ->
    {Pub, _Priv} = crypto:generate_key(eddsa, ed25519),
    Pub.

%% -> {Private32, Public64} — the public key without its 0x04 point prefix,
%% which is exactly the DNSKEY key material.
ec_generate() ->
    {Pub, Priv} = crypto:generate_key(ecdh, prime256v1),
    <<4, XY:64/binary>> = Pub,
    {pad32(Priv), XY}.

ecdsa_sign_raw(Msg, Priv32) ->
    Der = crypto:sign(ecdsa, sha256, Msg, [Priv32, prime256v1]),
    der_to_raw(Der).

ecdsa_verify_raw(Msg, RawSig, Pub64) ->
    case raw_to_der(RawSig) of
        error ->
            false;
        Der ->
            crypto:verify(ecdsa, sha256, Msg, Der,
                          [<<4, Pub64/binary>>, prime256v1])
    end.

%% DER/ASN.1 ECDSA — what a Rekor entry's signature.content carries, and
%% what the client's possession check verifies (crates/synch-net/src/rekor.rs
%% uses ECDSA_P256_SHA256_ASN1). :crypto signs and verifies DER natively, so
%% no r||s conversion here.
ecdsa_sign_der(Msg, Priv32) ->
    crypto:sign(ecdsa, sha256, Msg, [Priv32, prime256v1]).

ecdsa_verify_der(Msg, Der, Pub64) ->
    crypto:verify(ecdsa, sha256, Msg, Der,
                  [<<4, Pub64/binary>>, prime256v1]).

%% Ed25519 over a raw message — the signature scheme a tiled log's
%% checkpoints use. EdDSA hashes internally, so the algorithm digest is
%% `none`.
ed25519_verify(Msg, Sig, Pub32) ->
    crypto:verify(eddsa, none, Msg, Sig, [Pub32, ed25519]).

%% The same two verifications, guarded — for TUF metadata (tuf/verify), where
%% the key material and the signatures both come out of a file a hostile
%% mirror may have written.
%%
%% `crypto:verify/5` answers false for a signature that merely fails, but
%% *raises* for one it cannot parse at all, and for a public key of the wrong
%% length. Those are ordinary contents of a file being checked, not faults:
%% a root that lists one unusable key must fall to a threshold error, not
%% take the process down. Every other caller in this service hands these
%% functions material it has already parsed, which is why the unguarded forms
%% stay as they are.
ed25519_verify_safe(Msg, Sig, Pub32) ->
    try ed25519_verify(Msg, Sig, Pub32) catch _:_ -> false end.

%% DER first, since that is what Sigstore's TUF signatures are; the
%% fixed-width r||s form is the same signature written the other way, and the
%% client accepts both too.
ecdsa_verify_any_safe(Msg, Sig, Pub64) ->
    try ecdsa_verify_der(Msg, Sig, Pub64) of
        true -> true;
        false -> try ecdsa_verify_raw(Msg, Sig, Pub64) catch _:_ -> false end
    catch
        _:_ -> try ecdsa_verify_raw(Msg, Sig, Pub64) catch _:_ -> false end
    end.

pad32(Bin) when byte_size(Bin) =:= 32 -> Bin;
pad32(Bin) when byte_size(Bin) < 32 ->
    <<0:((32 - byte_size(Bin)) * 8), Bin/binary>>;
pad32(Bin) ->
    binary:part(Bin, byte_size(Bin) - 32, 32).

%% ECDSA P-256 signatures are always short-form DER (< 128 bytes total).
der_to_raw(<<16#30, _Len, 2, RL, Rest/binary>>) ->
    <<R:RL/binary, 2, SL, S:SL/binary>> = Rest,
    <<(fix32(R))/binary, (fix32(S))/binary>>.

%% DER integers drop leading zeros and add one back for a set high bit;
%% raw fields are fixed 32-byte big-endian.
fix32(B) ->
    S = strip_zeros(B),
    <<0:((32 - byte_size(S)) * 8), S/binary>>.

strip_zeros(<<0, Rest/binary>>) when byte_size(Rest) > 0 -> strip_zeros(Rest);
strip_zeros(B) -> B.

raw_to_der(<<R:32/binary, S:32/binary>>) ->
    RD = der_int(R),
    SD = der_int(S),
    Body = <<2, (byte_size(RD)), RD/binary, 2, (byte_size(SD)), SD/binary>>,
    <<16#30, (byte_size(Body)), Body/binary>>;
raw_to_der(_) ->
    error.

der_int(B) ->
    case strip_zeros(B) of
        <<H, _/binary>> = S when H >= 128 -> <<0, S/binary>>;
        S -> S
    end.

%% ------------------------------------------------------------------------
%% The zone-key certificate (docs/REKOR-ZONE-KEY.md §2).
%%
%% Rekor v2's verifier is a oneof — a raw public key or an X.509 certificate
%% — and it validates the certificate not at all: it parses it, takes the
%% public key, and copies the DER verbatim into the canonicalized body the
%% Merkle leaf commits to. That is the only door in a log with one entry type
%% and no room for a payload, so this is how the apex gets into the leaf
%% where a monitor can index it.
%%
%% What comes out is therefore a **key envelope, not a trust assertion**.
%% Nothing anywhere verifies its signature, its issuer or its validity
%% window; the three things that matter are the SubjectPublicKeyInfo, the
%% single dNSName SAN, and the two custom extensions carried through.
%%
%% Built with OTP's own public_key records rather than hand-rolled DER: the
%% ASN.1 module is the reference encoder, and a certificate an external tool
%% cannot read would defeat the point of putting it in a public log.
self_signed_cert(CommonName, DnsName, Pub64, Priv32, NotBefore, NotAfter,
                 Extra) ->
    Point = <<4, Pub64/binary>>,
    Name = {rdnSequence,
            [[#'AttributeTypeAndValue'{type = ?'id-at-commonName',
                                       value = {utf8String, CommonName}}]]},
    %% The serial is derived from the key, not drawn at random: re-running
    %% the ceremony for the same key must produce the same certificate, or
    %% every republish would mint a fresh Merkle leaf for one claim.
    <<Serial:128, _/binary>> = crypto:hash(sha256, Point),
    Extensions =
        [#'Extension'{extnID = ?'id-ce-basicConstraints', critical = true,
                      extnValue = #'BasicConstraints'{cA = false}},
         #'Extension'{extnID = ?'id-ce-keyUsage', critical = true,
                      extnValue = [digitalSignature]},
         %% Non-critical: criticality is an instruction to validators, and
         %% nothing validates this certificate.
         #'Extension'{extnID = ?'id-ce-subjectAltName', critical = false,
                      extnValue = [{dNSName, binary_to_list(DnsName)}]}]
        ++ [#'Extension'{extnID = Oid, critical = false, extnValue = Value}
            || {Oid, Value} <- Extra],
    Tbs = #'OTPTBSCertificate'{
             version = v3,
             serialNumber = Serial,
             signature = #'SignatureAlgorithm'{
                            algorithm = ?'ecdsa-with-SHA256',
                            parameters = asn1_NOVALUE},
             issuer = Name,
             validity = #'Validity'{notBefore = x509_time(NotBefore),
                                    notAfter = x509_time(NotAfter)},
             subject = Name,
             subjectPublicKeyInfo =
                 #'OTPSubjectPublicKeyInfo'{
                    algorithm = #'PublicKeyAlgorithm'{
                                   algorithm = ?'id-ecPublicKey',
                                   parameters = {namedCurve, ?'secp256r1'}},
                    subjectPublicKey = #'ECPoint'{point = Point}},
             extensions = Extensions},
    Key = #'ECPrivateKey'{version = 1, privateKey = Priv32,
                          parameters = {namedCurve, ?'secp256r1'},
                          publicKey = Point},
    public_key:pkix_sign(Tbs, Key).

%% RFC 5280 draws the line at 2050: UTCTime below it, GeneralizedTime above.
x509_time(Unix) ->
    {{Y, M, D}, {H, Mi, S}} =
        calendar:gregorian_seconds_to_datetime(Unix + 62167219200),
    case Y >= 1950 andalso Y =< 2049 of
        true ->
            {utcTime, lists:flatten(io_lib:format("~2..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
                                                  [Y rem 100, M, D, H, Mi, S]))};
        false ->
            {generalTime, lists:flatten(io_lib:format("~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
                                                      [Y, M, D, H, Mi, S]))}
    end.

%% The two things a reader turns on inside a zone-key certificate: the DER
%% SubjectPublicKeyInfo and the single dNSName SAN. Decoded with OTP's own
%% ASN.1 module, so this service reads its own certificates with the same
%% code that wrote them — and a certificate it cannot read is one it refuses
%% to store, rather than one it discovers a client rejecting later.
cert_spki_and_san(Der) ->
    try
        #'OTPCertificate'{tbsCertificate = Tbs} =
            public_key:pkix_decode_cert(Der, otp),
        #'Certificate'{tbsCertificate = Plain} =
            public_key:der_decode('Certificate', Der),
        Spki = public_key:der_encode(
                 'SubjectPublicKeyInfo',
                 Plain#'TBSCertificate'.subjectPublicKeyInfo),
        Extensions = Tbs#'OTPTBSCertificate'.extensions,
        case [Names || #'Extension'{extnID = ?'id-ce-subjectAltName',
                                    extnValue = Names} <- Extensions] of
            [Names] ->
                case [list_to_binary(N) || {dNSName, N} <- Names] of
                    [Name] -> {ok, {Spki, Name}};
                    _ -> {error, nil}
                end;
            _ -> {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.

%% One extension's DER value, by OID. Used to read back what was just
%% written — a certificate that lost its chain on the way through the
%% encoder would otherwise be discovered by a client, weeks later.
cert_extension(Der, Oid) ->
    try
        #'OTPCertificate'{tbsCertificate = Tbs} =
            public_key:pkix_decode_cert(Der, otp),
        case [Value || #'Extension'{extnID = O, extnValue = Value}
                           <- Tbs#'OTPTBSCertificate'.extensions, O =:= Oid] of
            [Value] when is_binary(Value) -> {ok, Value};
            _ -> {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.
