%% Test-only helpers: unique temp database paths, killing the csqlite
%% OS process out from under a connection for the crash-isolation test,
%% and a one-session SMTP server that hands back what the client said.
-module(test_ffi).
-export([tmp_db/0, kill9/1, rename/2, udp_roundtrip/2]).
-export([smtp_listen/0, smtp_transcript/0]).

tmp_db() ->
    %% unique_integer is only unique within one VM run; the wall clock keeps
    %% names from colliding with leftovers of earlier (crashed) runs.
    N = erlang:unique_integer([positive]),
    T = erlang:system_time(microsecond),
    Dir = filename:basedir(user_cache, "controlplane-tests"),
    ok = filelib:ensure_path(Dir),
    Name = io_lib:format("db-~B-~B.sqlite", [T, N]),
    unicode:characters_to_binary(filename:join(Dir, Name)).

kill9(OsPid) ->
    _ = os:cmd("kill -9 " ++ integer_to_list(OsPid)),
    nil.

rename(From, To) ->
    ok = file:rename(From, To),
    nil.

%% Serve exactly one SMTP session on an ephemeral port and remember the
%% client's half of it. `smtp_listen` returns the port to send to;
%% `smtp_transcript` then waits for the session to end and returns every
%% line the client sent, envelope commands and message alike.
smtp_listen() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false},
                                      {reuseaddr, true}, {packet, line}]),
    {ok, Port} = inet:port(Listen),
    Caller = self(),
    _ = spawn(fun() -> Caller ! {smtp_transcript, smtp_serve(Listen)} end),
    Port.

smtp_transcript() ->
    receive
        {smtp_transcript, Transcript} -> Transcript
    after 5000 -> <<"no session">>
    end.

smtp_serve(Listen) ->
    {ok, Socket} = gen_tcp:accept(Listen, 5000),
    ok = gen_tcp:send(Socket, "220 test ESMTP\r\n"),
    Lines = smtp_dialogue(Socket, [], command),
    gen_tcp:close(Socket),
    gen_tcp:close(Listen),
    iolist_to_binary(Lines).

smtp_dialogue(Socket, Said, body) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, <<".\r\n">> = Line} ->
            smtp_reply(Socket, "250 queued"),
            smtp_dialogue(Socket, [Line | Said], command);
        {ok, Line} ->
            smtp_dialogue(Socket, [Line | Said], body);
        {error, _} ->
            lists:reverse(Said)
    end;
smtp_dialogue(Socket, Said, command) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, Line} ->
            Next = [Line | Said],
            %% No STARTTLS and no AUTH on offer: this listener exists to
            %% record an envelope, not to be a relay.
            case string:uppercase(binary:part(Line, 0, min(4, byte_size(Line)))) of
                <<"EHLO">> ->
                    smtp_reply(Socket, "250-test greets you\r\n250 8BITMIME"),
                    smtp_dialogue(Socket, Next, command);
                <<"DATA">> ->
                    smtp_reply(Socket, "354 go ahead"),
                    smtp_dialogue(Socket, Next, body);
                <<"QUIT">> ->
                    smtp_reply(Socket, "221 bye"),
                    lists:reverse(Next);
                _ ->
                    smtp_reply(Socket, "250 ok"),
                    smtp_dialogue(Socket, Next, command)
            end;
        {error, _} ->
            lists:reverse(Said)
    end.

smtp_reply(Socket, Text) ->
    ok = gen_tcp:send(Socket, [Text, "\r\n"]).

udp_roundtrip(Port, Packet) ->
    {ok, S} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(S, {127, 0, 0, 1}, Port, Packet),
    R = case gen_udp:recv(S, 0, 2000) of
            {ok, {_, _, Resp}} -> {ok, Resp};
            {error, _} -> {error, nil}
        end,
    gen_udp:close(S),
    R.
