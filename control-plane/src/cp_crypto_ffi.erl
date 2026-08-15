%% Thin FFI over OTP :crypto for ECDSA P-256 (DNSSEC algorithm 13).
%% :crypto speaks DER-encoded signatures; DNSSEC wants raw r||s (64 bytes,
%% RFC 6605 §4) — the conversion lives here, next to the calls that need it.
-module(cp_crypto_ffi).
-export([ec_generate/0, ecdsa_sign_raw/2, ecdsa_verify_raw/3]).

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
