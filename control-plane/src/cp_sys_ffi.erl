%% Thin FFI for the two system facilities gleam_erlang does not expose:
%% wall-clock time and the program's arguments.
-module(cp_sys_ffi).
-export([now_unix/0, monotonic_ms/0, argv/0, priv_dir/1]).

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


argv() ->
    [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].

