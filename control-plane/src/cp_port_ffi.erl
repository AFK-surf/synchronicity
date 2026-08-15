%% Thin FFI over Erlang ports for the csqlite port program.
%% Framing is {packet,4} both ways; replies are delivered to the process
%% that opened the port, so a connection is single-owner by construction.
-module(cp_port_ffi).
-export([priv_path/1, open/2, rpc/3, close/1, os_pid/1]).

priv_path(File) ->
    case code:priv_dir(controlplane) of
        {error, _} ->
            {error, nil};
        Dir ->
            Path = filename:join(Dir, unicode:characters_to_list(File)),
            case filelib:is_regular(Path) of
                true -> {ok, unicode:characters_to_binary(Path)};
                false -> {error, nil}
            end
    end.

open(Exe, Args) ->
    ExeS = unicode:characters_to_list(Exe),
    ArgsS = [unicode:characters_to_list(A) || A <- Args],
    try
        Port = open_port({spawn_executable, ExeS},
                         [{packet, 4}, binary, use_stdio, exit_status, {args, ArgsS}]),
        %% Unlinked: the child dying must surface as {exit_status,_} data,
        %% not as an exit signal that kills a non-trapping owner. A janitor
        %% covers the gap that unlinking opens — if the owner dies first, it
        %% closes the port so the child sees EOF and exits (no orphans).
        erlang:unlink(Port),
        Owner = self(),
        spawn(fun() ->
            OwnerRef = erlang:monitor(process, Owner),
            PortRef = erlang:monitor(port, Port),
            receive
                {'DOWN', OwnerRef, process, _, _} -> catch erlang:port_close(Port);
                {'DOWN', PortRef, port, _, _} -> ok
            end
        end),
        {ok, Port}
    catch
        error:_ -> {error, nil}
    end.

%% The monitor is what makes death detection deterministic: a write to a
%% dead child can kill the port with epipe before any {exit_status,_}
%% message is produced, and the port is deliberately unlinked.
rpc(Port, Payload, TimeoutMs) ->
    Ref = erlang:monitor(port, Port),
    Result =
        try port_command(Port, Payload) of
            true ->
                receive
                    {Port, {data, Bin}} -> {ok, Bin};
                    {Port, {exit_status, _}} -> {error, closed};
                    {'DOWN', Ref, port, _, _} -> {error, closed};
                    {'EXIT', Port, _} -> {error, closed}
                after TimeoutMs -> {error, timeout}
                end
        catch
            error:badarg -> {error, closed}
        end,
    erlang:demonitor(Ref, [flush]),
    Result.

close(Port) ->
    catch port_close(Port),
    nil.

os_pid(Port) ->
    case erlang:port_info(Port, os_pid) of
        {os_pid, Pid} -> Pid;
        _ -> 0
    end.
