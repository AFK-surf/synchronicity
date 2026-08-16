#!/usr/bin/env perl
# Smoke-tests the csqlite sandbox from the outside, over the real frame
# protocol: a worker handed a scratch directory must behave normally
# inside it (OPEN, WAL, EXEC, RESET, CLOSE) and must be refused an
# out-of-directory create by the kernel, not by its own argument
# checking (it has none — the kernel is the authority).
#
# With CSQLITE_SMOKE_REQUIRE=1, missing enforcement is a failure; CI
# sets it on platforms whose kernels enforce the sandbox (ubuntu
# runners ship Landlock; unveil/pledge are unconditional on OpenBSD).
# Unset, missing enforcement only warns, so the script still passes on
# dev hosts without Landlock while catching protocol regressions.
#
# Perl, core modules only: present in OpenBSD base and on every CI
# image this runs on, so the two platforms share one script.
#
# Usage: perl smoke.pl path/to/csqlite

use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Handle;
use IPC::Open3 qw(open3);

my $exe = $ARGV[0] or die "usage: perl smoke.pl path/to/csqlite\n";
-x $exe or die "smoke: $exe is not executable (build csqlite first)\n";
my $require  = $ENV{CSQLITE_SMOKE_REQUIRE} ? 1 : 0;
my $failures = 0;

sub frame { pack("N", length $_[0]) . $_[0] }

# stderr is inherited: the worker's sandbox warnings belong in the CI
# log right next to the checks they explain.
sub spawn_worker {
    my ($datadir) = @_;
    my ($in, $out);
    my $pid = open3($in, $out, '>&STDERR', $exe, $datadir);
    binmode $in;
    binmode $out;
    $in->autoflush(1);
    return ($pid, $in, $out);
}

sub read_exact {
    my ($fh, $n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $got = sysread($fh, $buf, $n - length($buf), length($buf));
        die "smoke: worker closed the pipe mid-frame\n" unless $got;
    }
    return $buf;
}

sub rpc {
    my ($in, $out, $payload) = @_;
    print {$in} frame($payload);
    my $len = unpack("N", read_exact($out, 4));
    return read_exact($out, $len);
}

sub expect {
    my ($what, $resp, $tag) = @_;
    my $got = unpack("C", $resp);
    if ($got == $tag) {
        printf "ok   %-40s -> 0x%02x\n", $what, $got;
        return;
    }
    # ERR carries i32 code, u32 len, then the message (offset 9).
    my $detail = $got == 0x84 ? " (" . substr($resp, 9) . ")" : "";
    printf "FAIL %-40s -> 0x%02x, wanted 0x%02x%s\n", $what, $got, $tag,
        $detail;
    $failures++;
}

sub exec_frame {
    my ($sql) = @_;
    return "\x02" . pack("N", length $sql) . $sql . pack("n", 0);
}

# --- 1. Full life-cycle inside the granted directory. WAL + ORDER BY +
# RESET + CLOSE cover the syscalls the sandbox must keep allowing:
# shm mmap, journal fchmod, sort, reopen, unlink.

my $datadir = tempdir(CLEANUP => 1);
my ($pid, $in, $out) = spawn_worker($datadir);
expect("OPEN inside the sandbox dir",
    rpc($in, $out, "\x01\x02$datadir/t.db"), 0x81);

if ($^O eq 'linux') {
    my $status = do { local (@ARGV, $/) = ("/proc/$pid/status"); <> };
    my ($seccomp) = $status =~ /^Seccomp:\s*(\d+)/m;
    my ($nnp)     = $status =~ /^NoNewPrivs:\s*(\d+)/m;
    if (($seccomp // -1) == 2 && ($nnp // -1) == 1) {
        print "ok   seccomp filter + no_new_privs active\n";
    }
    elsif ($require) {
        printf "FAIL seccomp=%s no_new_privs=%s: syscall filter not "
            . "active\n", $seccomp // '?', $nnp // '?';
        $failures++;
    }
    else {
        print "warn seccomp filter not active; not required on this "
            . "host\n";
    }
}

expect("SCRIPT journal_mode=WAL",
    rpc($in, $out, "\x04PRAGMA journal_mode=WAL"), 0x81);
expect("SCRIPT create + insert",
    rpc($in, $out, "\x04CREATE TABLE t(a); INSERT INTO t VALUES(42)"),
    0x81);
expect("EXEC ordered select",
    rpc($in, $out, exec_frame("SELECT a FROM t ORDER BY a")), 0x83);
expect("RESET reopen", rpc($in, $out, "\x05"), 0x81);
expect("EXEC select after RESET",
    rpc($in, $out, exec_frame("SELECT a FROM t")), 0x83);
expect("CLOSE", rpc($in, $out, "\x03"), 0x81);
close $in;
waitpid($pid, 0);
if (my $code = $? >> 8) {
    print "FAIL worker exited $code after CLOSE\n";
    $failures++;
}

# --- 2. The kernel must refuse an OPEN outside the granted directory.

my $outside = tempdir(CLEANUP => 1);
($pid, $in, $out) = spawn_worker($datadir);
my $resp = rpc($in, $out, "\x01\x02$outside/escape.db");
if (unpack("C", $resp) == 0x84 && !-e "$outside/escape.db") {
    print "ok   out-of-dir OPEN refused by the kernel\n";
}
elsif ($require) {
    print "FAIL out-of-dir OPEN succeeded: filesystem confinement is "
        . "not enforced here\n";
    $failures++;
}
else {
    print "warn out-of-dir OPEN succeeded (kernel without Landlock?); "
        . "not required on this host\n";
}
unlink "$outside/escape.db";
close $in;
waitpid($pid, 0);

die "smoke: $failures check(s) failed\n" if $failures;
print "smoke: all checks passed\n";
