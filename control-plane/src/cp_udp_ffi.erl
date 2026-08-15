%% Thin FFI over inet/gen_udp for the DNS server. Socket functions arrive
%% with the port-53 milestone; parse_ip is needed as soon as glue records
%% exist.
-module(cp_udp_ffi).
-export([parse_ip/1, udp_open/1, udp_recv/2, udp_send/3]).

%% Passive-mode socket: the serving loop calls udp_recv, so datagrams
%% never race into an unbounded mailbox.
udp_open(Port) ->
    case gen_udp:open(Port, [binary, {active, false}, {reuseaddr, true}]) of
        {ok, Socket} -> {ok, Socket};
        {error, _} -> {error, nil}
    end.

udp_recv(Socket, TimeoutMs) ->
    case gen_udp:recv(Socket, 0, TimeoutMs) of
        {ok, {Ip, Port, Packet}} -> {ok, {{Ip, Port}, Packet}};
        {error, timeout} -> {error, timeout};
        {error, _} -> {error, closed}
    end.

udp_send(Socket, {Ip, Port}, Packet) ->
    case gen_udp:send(Socket, Ip, Port, Packet) of
        ok -> {ok, nil};
        {error, _} -> {error, nil}
    end.

parse_ip(Text) ->
    case inet:parse_address(unicode:characters_to_list(Text)) of
        {ok, {A, B, C, D}} ->
            {ok, <<A, B, C, D>>};
        {ok, {A, B, C, D, E, F, G, H}} ->
            {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
        _ ->
            {error, nil}
    end.
