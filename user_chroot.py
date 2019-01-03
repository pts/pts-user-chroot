#! /usr/bin/python
#
# user_chroot.py: doing chroot(2) without root access on Linux
# by pts@fazekas.hu at Mon Dec 31 13:57:19 CET 2018
#
# This is a proof-of-concept Python implementation using
# unshare(CLONE_NEWUSER). It works on Linux >= 3.8. In production please
# consider using https://github.com/pts/pts-chroot-env-qq instead.
#
# Code based on:
#
#   $ git clone https://github.com/cheshirekow/uchroot &&
#   $ cd uchroot
#   $ git checkout 4b3cf28765e17f9b6de74fcedfc78a5ace26bb77
#

import ctypes
import os
import sys


def get_glibc():
  glibc = ctypes.CDLL('libc.so.6', use_errno=True)

  # http://man7.org/linux/man-pages/man2/unshare.2.html
  glibc.unshare.restype = ctypes.c_int
  glibc.unshare.argtypes = [ctypes.c_int]

  # http://man7.org/linux/man-pages/man2/chroot.2.html
  glibc.chroot.restype = ctypes.c_int
  glibc.chroot.argtypes = [ctypes.c_char_p]

  # http://man7.org/linux/man-pages/man2/mount.2.html
  glibc.mount.restype = ctypes.c_int
  glibc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_uint,  # unsigned long
                          ctypes.c_void_p]

  glibc.CLONE_NEWUSER = 0x10000000
  glibc.CLONE_NEWNS = 0x20000
  glibc.CLONE_NEWIPC = 0x08000000
  glibc.MS_RDONLY = 0x1
  glibc.MS_BIND = 0x1000
  glibc.MS_REC = 0x4000
  glibc.MS_PRIVATE = 0x40000

  glibc.nullptr = ctypes.POINTER(ctypes.c_char)()

  return glibc


def make_sure_is_dir(need_dir, source):
  if not os.path.isdir(need_dir):
    if os.path.exists(need_dir):
      print >>sys.stderr, "removing rootdir bind target %s because it is not a directory" % need_dir
      os.remove(need_dir)
    print >>sys.stderr, "creating rootdir directory %s because it is needed to bind mount %s" % (need_dir, source)
    os.makedirs(need_dir)


def make_sure_is_file(need_path, source):
  make_sure_is_dir(os.path.dirname(need_path), source)

  if not os.path.exists(need_path):
    print >>sys.stderr, "creating rootdir regular file %s because it is a requested mount-point for %s" % (need_path, source)
    with open(need_path, 'wb') as touchfile:
      touchfile.write('# written by uchroot')


def main(argv):
  argv0 = argv.pop(0)
  if len(argv) != 2:
    print >>sys.stderr, 'Usage: %s <rootdir> <prog> [<arg> ...]' % argv0
    sys.exit(1)
  rootdir = argv.pop(0)
  env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}
  cwd = '/'
  binds = ['/proc', '/dev/pts']  # 'tmpfs:/var/tmp'.
  identity = (os.getuid(), os.getgid())

  # Pipes used to synchronize between the helper process and the chroot
  # process. Could also use eventfd, but this is simpler because python
  # already has os.pipe()
  helper_read_fd, primary_write_fd = os.pipe()
  primary_read_fd, helper_write_fd = os.pipe()
  parent_pid = os.getpid()
  uid, gid = os.getuid(), os.getgid()
  euid, egid = os.geteuid(), os.getegid()
  if uid != euid or gid != egid:
    print >>sys.stderr, 'fatal: real and effective UID or GID do not match'
    sys.exit(2)
  print >>sys.stderr, "info: Before unshare, uid=%d, gid=%d" % (uid, gid)
  glibc = get_glibc()

  if uid == 0:  # Running as root.
    # TODO(pts): What if root already in a container (user namespace)?
    os.setgroups([0])
  else:
    #err = glibc.unshare(glibc.CLONE_NEWIPC)
    #if err != 0:
    #  err = ctypes.get_errno()
    #  raise OSError(err, 'Failed to unshare IPC namespace: %s' % os.strerror(err))

    child_pid = os.fork()
    if child_pid == 0:  # Child.
      try:
        os.close(primary_read_fd)  # !! Close more.
        # Wait for the primary to create its new namespace
        os.read(helper_read_fd, 1)

        # Set the uid/gid map using the setuid helper programs
        open('/proc/%d/uid_map' % parent_pid, 'w').write('%d %d 1\n' % (uid, uid))  # OK.
        # !! why groups=65534(nogroup),65534(nogroup),65534(nogroup)?
        setgroups_path = '/proc/{}/setgroups'.format(parent_pid)
        with open(setgroups_path, 'wb') as setgroups:
          print >>sys.stderr, "info: Writing : %s (fd=%d)" % (setgroups_path, setgroups.fileno())
          setgroups.write("deny\n")  # !!
        print 'SETGR: %r' % open('/proc/%d/setgroups' % parent_pid).read()
        print 'GID: %r' % [os.getgid(), os.getegid()]
        f = open('/proc/%d/gid_map' % parent_pid, 'w'); f.write('%d %d 1\n' % (gid, gid)); f.close()  # !! Why: Fails: EPERM (Operation not permitted).

        # Inform the primary that we have finished setting its uid/gid map.
        os.write(helper_write_fd, '#')

        # NOTE(josh): using sys.exit() will interfere with the interpreter in the
        # parent process.
        # see: https://docs.python.org/3/library/os.html#os._exit
        os._exit(0)  # pylint: disable=protected-access
      except:
        traceback.print_exc()
        os._exit(-1)

    # First, unshare the user namespace and assume admin capability in the
    # new namespace.
    #
    # CLONE_NEWUSER needs Linux >=3.8 if run as non-root, otherwise EPERM.
    err = glibc.unshare(glibc.CLONE_NEWUSER)  # This needs Linux 3.8 to work without root.
    if err != 0:
      err = ctypes.get_errno()
      raise OSError(err, 'Failed to unshare user namespace: %s' % os.strerror(err))

    # Notify the helper that we have created the new namespace, and we need
    # it to set our uid/gid map.
    print >>sys.stderr, "Waiting for helper to set my uid/gid map"
    os.write(primary_write_fd, "#")

    # Wait for the helper to finish setting our uid/gid map.
    os.read(primary_read_fd, 1)
    print >>sys.stderr, "Helper has finished setting my uid/gid map"
    pid2, status = os.waitpid(child_pid, 0)
    if status:
      print >>sys.stderr, 'fatal: child failed with status=0x%x' % status

  err = glibc.unshare(glibc.CLONE_NEWNS)
  if err != 0:
    err = ctypes.get_errno()
    raise OSError(err, 'Failed to unshare mount namespace: %s' % os.strerror(err))

  # Without this call CLONE_NEWS doesn't take effect when run as root.
  err = glibc.mount("none", "/", glibc.nullptr, glibc.MS_REC | glibc.MS_PRIVATE, glibc.nullptr)
  if err != 0:
    err = ctypes.get_errno()
    raise OSError(err, 'Failed to remount / MS_PRIVATE: %s' % os.strerror(err))

  for bind_spec in binds:
    if isinstance(bind_spec, (list, tuple)):
      source, dest = bind_spec
    elif ':' in bind_spec:
      source, dest = bind_spec.split(':')
    else:
      source = bind_spec
      dest = bind_spec

    dest = dest.lstrip('/')
    rootdir_dest = os.path.join(rootdir, dest)
    print >>sys.stderr, 'Binding: %s -> %s' % (source, rootdir_dest)
    if source != 'tmpfs':
      assert os.path.exists(source), "source directory to bind does not exit {}".format(source)

    # Create the mountpoint if it is not already in the rootdir.
    if os.path.isdir(source):
      make_sure_is_dir(rootdir_dest, source)
    else:
      make_sure_is_file(rootdir_dest, source)

    if source.lstrip('/') == 'proc':
      # NOTE(josh): user isn't allowed to mount proc without MS_REC, see
      # https://stackoverflow.com/a/23435317
      # !! special filesystem type for /dev/pts
      err = glibc.mount(source, rootdir_dest, "proc", glibc.MS_REC | glibc.MS_BIND, glibc.nullptr)
    elif source == 'tmpfs':  # !!
      err = glibc.mount(source, rootdir_dest, "tmpfs", 0, "size=100000")  # !! configurable size
    else:
      # !! Optional MS_RDONLY
      err = glibc.mount(source, rootdir_dest, glibc.nullptr, glibc.MS_REC | glibc.MS_BIND, glibc.nullptr)
    if err != 0:
      err = ctypes.get_errno()
      raise OSError(err, 'Failed to mount %r: %s' % (rootdir_dest, os.strerror(err)))

  err = glibc.chroot(rootdir)
  if err != 0:
    raise OSError(err, "Failed to chroot: %s" % rootdir)

  os.chdir(cwd)

  # chroot and mount still work here, but it fails after the execve call.
  try:
    os.execvpe(argv[0], argv, env)
    raise OSError(-1, 'Failed to execve.')
  except OSError, e:
    raise OSError(e[0], 'Failed to start %r: %s' % (argv[0], os.strerror(e[0])))


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv))
  except OSError, e:
    print >>sys.stderr, 'fatal: %s' % e
