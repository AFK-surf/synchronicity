%% Thin FFI over inet/gen_udp for the DNS server. Socket functions arrive
%% with the port-53 milestone; parse_ip is needed as soon as glue records
%% exist.
-module(cp_udp_ffi).
-export([parse_ip/1]).

parse_ip(Text) ->
    case inet:parse_address(unicode:characters_to_list(Text)) of
        {ok, {A, B, C, D}} ->
            {ok, <<A, B, C, D>>};
        {ok, {A, B, C, D, E, F, G, H}} ->
            {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
        _ ->
            {error, nil}
    end.
