#! /usr/bin/perl -w
#
# user_chroot.pl: doing chroot(2) without root access on Linux
# by pts@fazekas.hu at Mon Dec 31 15:31:01 CET 2018
#
# This implementation uses unshare(CLONE_NEWUSER). It works on Linux >= 3.8.
# In production please consider using https://github.com/pts/pts-chroot-env-qq
# instead.
#

use integer;
use strict;

sub CLONE_NEWUSER() { 0x10000000 }  # New user namespace.
sub CLONE_NEWNS() { 0x20000 }       # New mount namespace.
sub CLONE_NEWIPC() { 0x08000000 }   # New IPC namespace.
sub MS_RDONLY() { 0x1 }
sub MS_BIND() { 0x1000 }
sub MS_REC() { 0x4000 }
sub MS_PRIVATE() { 0x40000 }

sub parse_mount_spec($) {
  my $mount = $_[0];
  # Using $fstype="proc" and no MS_BIND would give use EPERM.
  # /proc needs MS_REC. (Why?)
  my($device, $destdir, $fstype, $flags, $options) = ("none", undef, 0, MS_REC, 0);
  if ($mount =~ /\Atmpfs:(\d+):(.+)\Z(?!\n)/) {
    my $size = $1 + 1;
    ($fstype, $options, $destdir) = ("tmpfs", "size=$size", $2);
  } elsif ($mount =~ /\A(ro|rw):(?:([^:]+):)?(.+)\Z(?!\n)/) {
    $flags |= MS_RDONLY if $1 eq "ro";
    $flags |= MS_BIND;
    ($device, $destdir) = (defined($2) ? $2 : $3, $3);
  } else {
    # TODO(pts): Report earlier.
    die "fatal: bad mount spec: $mount\n";
  }
  $destdir =~ s@/+\Z(?!\n)@@;
  $destdir =~ s@\A/+@@;
  $destdir =~ s@/+@/@g;
  # TODO(pts): Report earlier.
  die "fatal: / not allowed as mount destination\n" if 0 == length($destdir);
  return ($device, $destdir, $fstype, $flags, $options)
}

die "Usage: $0 [<flag> ...] <rootdir> <prog> [<arg> ...]
Flags:
--cwd=<dir>  Change to this directory within <rootdir>. Default: /
--ro=[<source>:]<dir>  Bind-mount <dir> read-only.
--rw=[<source>:]<dir>  Bind-mount <dir> read-write.
--tmpfs=<bytesize>:<dir>  Mount in-memory tmps to <dir>.
" if !@ARGV or $ARGV[0] eq "--help";
my $cwd = "/";
my @mounts;
my $i;
for ($i = 0; $i < @ARGV; ) {
  my $arg = $ARGV[$i];
  last if substr($arg, 0, 1) ne "-";
  ++$i;
  last if $arg eq "--";
  if ($arg =~ /\A--cwd=(.*)\Z/s) { $cwd = $1 }
  elsif ($arg =~ /\A--(ro|rw|tmpfs)=(.*)\Z/s) { push @mounts, [parse_mount_spec("$1:$2")] }
  else { die "fatal: unknown command-line flag: $arg\n" }
}
die "fatal: too few command-line arguments\n" if $i + 2 > @ARGV;
my $rootdir = $ARGV[$i++];
$rootdir =~ s@/+\Z(?!\n)@@;
splice(@ARGV, 0, $i);
# Use --rw=/ to disable the default.
push @mounts, map { [parse_mount_spec($_)] } "rw:/proc", "rw:/dev/pts" if !@mounts;

die "fatal: root directory does not exist: $rootdir\n" if !-d($rootdir);
# Just a precaution.
die "fatal: UID mismatch (running as setuid?)\n" if $< + 0 != $> + 0;
die "fatal: GID mismatch (running as setgid?)\n" if $( + 0 != $) + 0;

# Needed by CLONE_NEWNS and MS_BIND.
die "fatal: Linux operating system needed\n" if $^O ne "linux";
# We figure out the architecture of the current process by opening the Perl
# interpreter binary. Doing `require POSIX; die((POSIX::uname())[4])'
# wouldn't work, because it would return x86_64 for an i386 process running
# on an amd64 kernel.
my $perl_prog = $^X;
if ($perl_prog !~ m@/@) {
  # Perl 5.004 does not have a path to "perl" in $^X, it just has "perl".
  # We look it up on $ENV{PATH}.
  my $perl_filename = $perl_prog;
  $perl_prog = undef;
  for my $dir (split(/:+/, $ENV{PATH})) {
    next if !length($dir);
    $perl_prog = "$dir/$perl_filename";
    last if -e $perl_prog;
    $perl_prog = undef;
  }
  die "fatal: Perl interpreter not found on \$ENV{PATH}: $perl_filename\n" if
      !defined($perl_prog);
}
local *FH;
die "fatal: open $^X: $!\n" if !open(FH, "< $perl_prog");
my $got = sysread(FH, $_, 52);
die "fatal: read $^X: $!\n" if ($got or 0) < 52;
die "fatal: close $^X: $!\n" if !close(FH);
my $arch = "unknown";
my ($SYS_mount, $SYS_unshare);
# All architectures supported by Debian 9 Stretch are here, plus some more.
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header
# System call numbers: https://fedora.juszkiewicz.com.pl/syscalls.html
if (/\A\x7FELF\x02\x01\x01[\x00\x03]........[\x02\x03]\x00\x3E/s) {
  $arch = "amd64";  # x86_64, x64.
  ($SYS_mount, $SYS_unshare) = (165, 272);
} elsif (/\A\x7FELF\x02\x01\x01[\x00\x03]........[\x02\x03]\x00\xB7/s) {
  $arch = "aarch64";  # arm64.
  ($SYS_mount, $SYS_unshare) = (40, 97);
} elsif (/\A\x7FELF\x01\x01\x01[\x00\x03]........[\x02\x03]\x00\x03/s) {
  $arch = "i386";  # i486, i586, i686, x86.
  ($SYS_mount, $SYS_unshare) = (21, 310);
} elsif (/\A\x7FELF\x01\x01\x01[\x00\x03]........[\x02\x03]\x00\x28/s) {
  $arch = "arm";  # arm32, armel, armhf.
  ($SYS_mount, $SYS_unshare) = (21, 337);
} elsif (/\A\x7FELF\x02\x02\x01[\x00\x03]........\x00[\x02\x03]\x00/s) {
  $arch = "s390x";  # s390. s390x for Debian 9. Last byte is 0 (no architecture).
  ($SYS_mount, $SYS_unshare) = (21, 303);
} elsif (/\A\x7FELF\x01\x02\x01[\x00\x03]........\x00[\x02\x03][\x00\x08]/s) {
  $arch = "mips";  # mips for Debian 9. Last byte is 0 (no architecture).
  ($SYS_mount, $SYS_unshare) = (4021, 4303);
} elsif (/\A\x7FELF\x02\x01\x01[\x00\x03]........[\x02\x03]\x00\x08/s) {
  $arch = "mips64el";
  ($SYS_mount, $SYS_unshare) = (5160, 5262);  # For mips64n32, SYS_unshare is 6266.
} elsif (/\A\x7FELF\x01\x01\x01[\x00\x03]........[\x02\x03]\x00\x08/s) {
  $arch = "mipsel";  # Like mips, but LSB-first (little endiel).
  ($SYS_mount, $SYS_unshare) = (4021, 4303);
} elsif (/\A\x7FELF\x02\x01\x01[\x00\x03]........[\x02\x03]\x00\x15/s) {
  $arch = "ppc64el";  # ppc64, powerpc64.
  ($SYS_mount, $SYS_unshare) = (21, 282);
} elsif (/\A\x7FELF\x01\x01\x01[\x00\x03]........[\x02\x03]\x00\x15/s) {
  $arch = "ppc32el";  # ppc32, powerpc32, powerpc.
  ($SYS_mount, $SYS_unshare) = (21, 282);
} else {
  die "fatal: unknown architecture for the Perl process\n";
}

if ($> == 0) {  # Running as root.
  $) = "".($) + 0)." ".($) + 0);  # setgroups([]).
} else {
  my $pid = $$;
  local (*HR, *PW, *PR, *HW);
  die "fatal: pipe1: $!\n" if !pipe(HR, PW);
  die "fatal: pipe2: $!\n" if !pipe(PR, HW);
  my $child_pid = fork();
  die "fatal: fork: $!\n" if !defined($child_pid);
  if (!$child_pid) {  # Child process.
    close(PR); close(PW);
    # Wait for parent do CLONE_NEWUSER first.
    exit(-1) if !sysread(HR, $_, 1);
    local *FH;
    die "fatal: child: open uid_map: $!\n" if !open(FH, "> /proc/$pid/uid_map");
    $_ = "$> $> 1\n";
    die "fatal: child: write uid_map: $!\n" if (syswrite(FH, $_, length($_)) or 0) != length($_);
    die "fatal: child: close uid_map: $!\n" if !close(FH);
    die "fatal: child: open setgroups: $!\n" if !open(FH, "> /proc/$pid/setgroups");
    # This disables the groups: groups=65534(nogroup),65534(nogroup),... .
    $_ = "deny\n";
    die "fatal: child: write setgroups: $!\n" if (syswrite(FH, $_, length($_)) or 0) != length($_);
    die "fatal: child: close setgroups: $!\n" if !close(FH);
    die "fatal: child: open gid_map: $!\n" if !open(FH, "> /proc/$pid/gid_map");
    $_ = ($) + 0)." ".($) + 0)." 1\n";
    die "fatal: child: write gid_map: $!\n" if (syswrite(FH, $_, length($_)) or 0) != length($_);
    die "fatal: child: close gid_map: $!\n" if !close(FH);
    $_ = "B";
    die "fatal: child: write helper: $!\n" if !syswrite(HW, $_, 1);
    exit(0);
  }

  close(HR); close(HW);
  # CLONE_NEWUSER needs Linux >=3.8 if run as non-root, otherwise EPERM.
  die "fatal: CLONE_NEWUSER: $!\n" if syscall($SYS_unshare, CLONE_NEWUSER);
  $_ = "A";
  # Signal the child that it can start writing files in /proc.
  die "fatal: child: write primary: $!\n" if !syswrite(PW, $_, 1);
  # Wait for the child to finish writing to /proc.
  die "fatal: error in child\n" if !sysread(PR, $_, 1);
  close(PR); close(PW);
  my $child_pid2 = waitpid($child_pid, 0);
  die "fatal: bad child_pid2\n" if $child_pid2 != $child_pid;
  die "fatal: error in child: ".sprintf("0x%x")."$?\n" if $?;
}

die "fatal: CLONE_NEWNS: $!\n" if syscall($SYS_unshare, CLONE_NEWNS);
{
  # Without this call CLONE_NEWS doesn't take effect when run as root.
  my @spec = ("none", "/", 0, MS_REC | MS_PRIVATE, 0);
  die "fatal: mount /: $!\n" if syscall($SYS_mount, @spec);
}
# chroot and mount still work here, but it fails after the execve call.
for my $spec (@mounts) {  # TODO(pts): Sort the mounts from root to leaves.
  my $destdir = $spec->[1];
  $spec->[1] = "$rootdir/$destdir";
  # TODO(pts): Create $destdir as file or directory if not exists.
  die "fatal: mount $destdir: $!\n" if syscall($SYS_mount, @$spec);
}
die "fatal: chroot $rootdir: $!\n" if !chroot($rootdir);
die "fatal: cd $cwd: $!\n" if !chdir($cwd);  # Within $rootdir.
die "fatal: exec $ARGV[0]: $!\n" if !exec(@ARGV);

__END__
