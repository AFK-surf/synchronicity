%% Thin FFI for the two system facilities gleam_erlang does not expose:
%% wall-clock time and the program's arguments.
-module(cp_sys_ffi).
-export([now_unix/0, monotonic_ms/0, mailbox_len/0, argv/0, priv_dir/1]).

priv_dir(Sub) ->
    case code:priv_dir(controlplane) of
        {error, _} ->
            {error, nil};
        Dir ->
            Path = filename:join(Dir, unicode:characters_to_list(Sub)),
            case filelib:is_dir(Path) of
                true -> {ok, unicode:characters_to_binary(Path)};
                false -> {error, nil}
            end
    end.

now_unix() ->
    erlang:system_time(second).

%% Milliseconds from a monotonic source, for bounding how long a walk may
%% run. Monotonic rather than wall-clock on purpose: a deadline that a clock
%% step could move is not a deadline.
monotonic_ms() ->
    erlang:monotonic_time(millisecond).

%% How many messages are sitting unread in the calling process's mailbox.
%%
%% For asserting that a request abandons no reply subject: an answer nothing
%% receives is invisible to every ordinary test, and accumulates in whichever
%% long-lived process did the asking until that connection closes.
mailbox_len() ->
    {message_queue_len, N} = erlang:process_info(self(), message_queue_len),
    N.


argv() ->
    [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].

