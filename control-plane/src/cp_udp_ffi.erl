%% Thin FFI over inet/gen_udp for the supervised DNS server, plus
%% parse_ip for glue-record addresses (dns/rdata).
-module(cp_udp_ffi).
-export([parse_ip/1, udp_send/3, udp_open_active/2, udp_active_once/1,
         udp_event/1, valid_listen/1]).

%% Active-once socket for the supervised server: datagrams arrive as
%% messages (one at a time — reactivated after each is handled), and
%% socket death arrives as a message too, so the owning actor can exit
%% abnormally and be restarted instead of dying silently.
valid_listen(Address) ->
    case listen_ip(Address) of
        {ok, _} -> true;
        error -> false
    end.

udp_open_active(Address, Port) ->
    case listen_ip(Address) of
        {ok, Ip} ->
            Family = case tuple_size(Ip) of
                         4 -> inet;
                         8 -> inet6
                     end,
            case gen_udp:open(Port, [Family, binary, {active, once},
                                     {reuseaddr, true}, {ip, Ip}]) of
                {ok, Socket} -> {ok, Socket};
                {error, _} -> {error, nil}
            end;
        error ->
            {error, nil}
    end.

listen_ip(Address) when is_binary(Address) ->
    listen_ip(unicode:characters_to_list(Address));
listen_ip("localhost") ->
    {ok, {127, 0, 0, 1}};
listen_ip(Address) when is_list(Address) ->
    case inet:parse_address(Address) of
        {ok, Ip} -> {ok, Ip};
        {error, _} -> error
    end.

udp_active_once(Socket) ->
    case inet:setopts(Socket, [{active, once}]) of
        ok -> {ok, nil};
        {error, _} -> {error, nil}
    end.

%% Classifies a raw active-mode message for the Gleam actor.
udp_event({udp, _Socket, Ip, Port, Packet}) -> {packet, {Ip, Port}, Packet};
udp_event({udp_closed, _Socket}) -> socket_closed;
udp_event(_) -> socket_error.

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
