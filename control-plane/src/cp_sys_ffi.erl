%% Thin FFI for the two system facilities gleam_erlang does not expose:
%% wall-clock time and the program's arguments.
-module(cp_sys_ffi).
-export([now_unix/0, argv/0]).

now_unix() ->
    erlang:system_time(second).

argv() ->
    [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].
