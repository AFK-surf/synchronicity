%% Thin FFI over gen_smtp's blocking client. One function: send one plain
%% text message through the configured relay.
%%
%% `Envelope` is the bare address for `MAIL FROM`; `From` is the header,
%% which may carry a display name. gen_smtp wraps the envelope address in
%% angle brackets itself, so handing it `Name <addr>` produces the
%% syntactically invalid `MAIL FROM:<Name <addr>>` and the relay rejects
%% the transaction before any message exists.
-module(cp_smtp_ffi).
-export([send/9]).

%% A failed send is a returned error, never an exception: the callers are
%% request handlers that owe their caller a response whatever the relay,
%% the DNS or the local trust store is doing.
send(Envelope, From, To, Subject, Body, Host, Port, Username, Password) ->
    try
        deliver(Envelope, From, To, Subject, Body, Host, Port, Username, Password)
    catch
        Class:Reason ->
            {error, unicode:characters_to_binary(
                      io_lib:format("~p:~p", [Class, Reason]))}
    end.

deliver(Envelope, From, To, Subject, Body, Host, Port, Username, Password) ->
    Message = iolist_to_binary([
        "Date: ", smtp_util:rfc5322_timestamp(), "\r\n",
        "Message-ID: ", smtp_util:generate_message_id(), "\r\n",
        "Subject: ", Subject, "\r\n",
        "From: ", From, "\r\n",
        "To: ", To, "\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n\r\n",
        Body
    ]),
    %% A relay that takes a password gets TLS or nothing: gen_smtp's
    %% `if_available` quietly continues in the clear when STARTTLS fails,
    %% which would put the credential on the wire.
    Auth = case Username of
        <<>> -> [{tls, if_available}];
        _ ->
            [{tls, always},
             {auth, always},
             {username, unicode:characters_to_list(Username)},
             {password, unicode:characters_to_list(Password)}]
    end,
    Hostname = unicode:characters_to_list(Host),
    %% `CP_SMTP_HOST` names the relay to talk to. Left to itself gen_smtp
    %% would look the name's MX up and go wherever that points instead.
    Options = [{relay, Hostname},
               {port, Port},
               {no_mx_lookups, true},
               {tls_options, tls_options(Hostname)} | Auth],
    case gen_smtp_client:send_blocking({Envelope, [To], Message}, Options) of
        Receipt when is_binary(Receipt) -> {ok, nil};
        {error, Type, Detail} ->
            {error, unicode:characters_to_binary(
                      io_lib:format("~p: ~p", [Type, Detail]))};
        {error, Reason} ->
            {error, unicode:characters_to_binary(io_lib:format("~p", [Reason]))}
    end.

%% gen_smtp's default is TLS 1.0-1.2 with no certificate verification at
%% all. Verify the relay, and offer versions this decade's servers still
%% negotiate.
tls_options(Hostname) ->
    [{versions, ['tlsv1.2', 'tlsv1.3']},
     {verify, verify_peer},
     {depth, 10},
     {cacerts, public_key:cacerts_get()},
     {server_name_indication, Hostname},
     {customize_hostname_check,
      [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}].
