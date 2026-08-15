%% Thin FFI for the two system facilities gleam_erlang does not expose:
%% wall-clock time and the program's arguments.
-module(cp_sys_ffi).
-export([now_unix/0, argv/0, snapshot_put/1, snapshot_get/0, priv_dir/1]).

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

argv() ->
    [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].

%% The zone snapshot lives in persistent_term: reads are zero-copy from
%% every process, and writes happen only on publish/reload, which is
%% exactly the access pattern persistent_term is built for.
snapshot_put(Snapshot) ->
    persistent_term:put({controlplane, snapshot}, Snapshot),
    nil.

snapshot_get() ->
    try
        {ok, persistent_term:get({controlplane, snapshot})}
    catch
        error:badarg -> {error, nil}
    end.
