pts-user-chroot: doing chroot(2) without root access on Linux
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
pts-user-chroot contains a Python and a Perl script implementing entering to
a chroot environment as a regular user (i.e. rootless, without root access,
without sudo, using unshare(CLONE_NEWUSER)).

The scripts work works on Linux >= 3.8.

In production please consider using https://github.com/pts/pts-chroot-env-qq
instead.

A similar Python project: https://github.com/cheshirekow/uchroot

__END__
