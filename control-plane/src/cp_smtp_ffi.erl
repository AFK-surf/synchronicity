%% Thin FFI over gen_smtp's blocking client. One function: send one plain
%% text message through the configured relay.
-module(cp_smtp_ffi).
-export([send/8]).

send(From, To, Subject, Body, Host, Port, Username, Password) ->
    Message = iolist_to_binary([
        "Subject: ", Subject, "\r\n",
        "From: ", From, "\r\n",
        "To: ", To, "\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n\r\n",
        Body
    ]),
    Auth = case Username of
        <<>> -> [];
        _ ->
            [{username, unicode:characters_to_list(Username)},
             {password, unicode:characters_to_list(Password)}]
    end,
    Options = [{relay, unicode:characters_to_list(Host)},
               {port, Port},
               {tls, if_available} | Auth],
    case gen_smtp_client:send_blocking({From, [To], Message}, Options) of
        Receipt when is_binary(Receipt) -> {ok, nil};
        {error, Type, Detail} ->
            {error, unicode:characters_to_binary(
                      io_lib:format("~p: ~p", [Type, Detail]))};
        {error, Reason} ->
            {error, unicode:characters_to_binary(io_lib:format("~p", [Reason]))}
    end.
