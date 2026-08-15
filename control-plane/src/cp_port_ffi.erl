%% Thin FFI over Erlang ports for the csqlite port program.
%% Framing is {packet,4} both ways; replies are delivered to the process
%% that opened the port, so a connection is single-owner by construction.
-module(cp_port_ffi).
-export([priv_path/1, open/2, rpc/3, close/1, os_pid/1, give/2, take/1,
         kill/1]).

%% Ownership transfer, for pooling: the current owner hands the port to
%% Pid. port_connect links Pid<->Port, so the receiver must call take/1
%% to drop that link — death detection is rpc/3's monitor, and an
%% unlinked port cannot kill a non-trapping owner.
give(Port, Pid) ->
    try
        true = erlang:port_connect(Port, Pid),
        erlang:unlink(Port),
        {ok, nil}
    catch
        error:_ -> {error, nil}
    end.

take(Port) ->
    catch erlang:unlink(Port),
    nil.

%% Force-close from any process (ownership not required): reclaims
%% workers whose borrower died holding them.
kill(Port) ->
    catch erlang:port_close(Port),
    nil.

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
    case Result of
        {error, timeout} ->
            %% The reply for this request is still coming. If the port
            %% survived, that stale frame would be matched by the NEXT
            %% rpc on this connection and returned as the wrong query's
            %% result — so a timed-out connection is killed, exactly as
            %% the Gleam docs promise. (Selective receive matches on the
            %% port identity, so a late frame from this dead port can
            %% never satisfy a future connection's receive.)
            catch erlang:port_close(Port),
            Result;
        _ ->
            Result
    end.

close(Port) ->
    catch port_close(Port),
    nil.

os_pid(Port) ->
    case erlang:port_info(Port, os_pid) of
        {os_pid, Pid} -> Pid;
        _ -> 0
    end.
