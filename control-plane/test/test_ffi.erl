%% Test-only helpers: unique temp database paths, and killing the csqlite
%% OS process out from under a connection for the crash-isolation test.
-module(test_ffi).
-export([tmp_db/0, kill9/1]).

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
