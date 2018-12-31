#! /usr/bin/python
#
# user_chroot.py: doing chroot while
# by pts@fazekas.hu at Mon Dec 31 13:57:19 CET 2018
#
# Based on: git clone https://github.com/cheshirekow/uchroot && cd uchroot && git checkout 4b3cf28765e17f9b6de74fcedfc78a5ace26bb77
#

import ctypes
import errno
import inspect
import io
import json
import logging
import os
import pprint
import pwd
import re
import subprocess
import sys
import tempfile
import textwrap


def get_glibc():
  """
  Return a ctypes wrapper around glibc. Only wraps functions needed by this
  script.
  """

  glibc = ctypes.CDLL('libc.so.6', use_errno=True)

  # http://man7.org/linux/man-pages/man2/getuid.2.html
  glibc.getuid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getuid.argtypes = []

  # http://man7.org/linux/man-pages/man2/getgid.2.html
  glibc.getgid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getgid.argtypes = []

  # http://man7.org/linux/man-pages/man2/unshare.2.html
  glibc.unshare.restype = ctypes.c_int
  glibc.unshare.argtypes = [ctypes.c_int]

  # http://man7.org/linux/man-pages/man2/getpid.2.html
  glibc.getpid.restype = ctypes.c_int  # pid_t, int32_t on my system
  glibc.getpid.argtypes = []

  # http://man7.org/linux/man-pages/man2/chroot.2.html
  glibc.chroot.restype = ctypes.c_int
  glibc.chroot.argtypes = [ctypes.c_char_p]

  # http://man7.org/linux/man-pages/man2/setresuid.2.html
  glibc.setresuid.restype = ctypes.c_int
  glibc.setresuid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
  glibc.setresgid.restype = ctypes.c_int
  glibc.setresgid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]

  # http://man7.org/linux/man-pages/man2/mount.2.html
  glibc.mount.restype = ctypes.c_int
  glibc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_uint,  # unsigned long
                          ctypes.c_void_p]

  glibc.CLONE_NEWUSER = 0x10000000
  glibc.CLONE_NEWNS = 0x20000
  glibc.MS_RDONLY = 0x1
  glibc.MS_BIND = 0x1000
  glibc.MS_REC = 0x4000

  return glibc


# NOTE(josh): see http://man7.org/linux/man-pages/man5/subuid.5.html on
# subordinate UIDs.
# https://lwn.net/Articles/532593/



def get_glibc():
  """
  Return a ctypes wrapper around glibc. Only wraps functions needed by this
  script.
  """

  glibc = ctypes.CDLL('libc.so.6', use_errno=True)

  # http://man7.org/linux/man-pages/man2/getuid.2.html
  glibc.getuid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getuid.argtypes = []

  # http://man7.org/linux/man-pages/man2/getgid.2.html
  glibc.getgid.restype = ctypes.c_uint  # gid_t, uint32_t on my system
  glibc.getgid.argtypes = []

  # http://man7.org/linux/man-pages/man2/unshare.2.html
  glibc.unshare.restype = ctypes.c_int
  glibc.unshare.argtypes = [ctypes.c_int]

  # http://man7.org/linux/man-pages/man2/getpid.2.html
  glibc.getpid.restype = ctypes.c_int  # pid_t, int32_t on my system
  glibc.getpid.argtypes = []

  # http://man7.org/linux/man-pages/man2/chroot.2.html
  glibc.chroot.restype = ctypes.c_int
  glibc.chroot.argtypes = [ctypes.c_char_p]

  # http://man7.org/linux/man-pages/man2/setresuid.2.html
  glibc.setresuid.restype = ctypes.c_int
  glibc.setresuid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
  glibc.setresgid.restype = ctypes.c_int
  glibc.setresgid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]

  # http://man7.org/linux/man-pages/man2/mount.2.html
  glibc.mount.restype = ctypes.c_int
  glibc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_uint,  # unsigned long
                          ctypes.c_void_p]

  glibc.CLONE_NEWUSER = 0x10000000
  glibc.CLONE_NEWNS = 0x20000
  glibc.MS_BIND = 0x1000
  glibc.MS_REC = 0x4000

  return glibc


def make_sure_is_dir(need_dir, source):
  """
  Ensure that the given path is a directory, removing a regular file if
  there is one at that location, creating the directory and all its
  parents if needed.
  """

  if not os.path.isdir(need_dir):
    if os.path.exists(need_dir):
      logging.warn("removing rootfs bind target %s because it"
                   " is not a directory\n", need_dir)
      os.remove(need_dir)
    logging.warn("creating rootfs directory %s because it is "
                 " needed to bind mount %s.\n", need_dir, source)
    os.makedirs(need_dir)


def make_sure_is_file(need_path, source):
  """
  Ensure that the parent directory of need_path exists, and that there is
  a regular file at that location, creating them if needed.
  """
  make_sure_is_dir(os.path.dirname(need_path), source)

  if not os.path.exists(need_path):
    logging.warn("creating rootfs regular file %s because it "
                 " is a requested mount-point for %s\n", need_path, source)
    with open(need_path, 'wb') as touchfile:
      touchfile.write('# written by uchroot')


def enter(read_fd, write_fd, rootfs=None, binds=None, identity=None,
          cwd=None):
  """
  Chroot into rootfs with a new user and mount namespace, then execute
  the desired command.
  """
  # pylint: disable=too-many-locals,too-many-statements

  if not binds:
    binds = []
  if not identity:
    identity = [0, 0]
  if not cwd:
    cwd = '/'

  glibc = get_glibc()
  uid = glibc.getuid()
  gid = glibc.getgid()

  logging.debug("Before unshare, uid=%d, gid=%d\n", uid, gid)
  # ---------------------------------------------------------------------
  #                     Create User Namespace
  # ---------------------------------------------------------------------

  # First, unshare the user namespace and assume admin capability in the
  # new namespace
  # !! Before Linux 3.8, use of CLONE_NEWUSER required that the caller have three capabilities: CAP_SYS_ADMIN, CAP_SETUID, and CAP_SETGID.  Starting with Linux 3.8, no privileges are needed to create a user namespace.
  err = glibc.unshare(glibc.CLONE_NEWUSER)
  if err != 0:
    raise OSError(err, "Failed to unshared user namespace", None)

  # write a uid/pid map
  pid = glibc.getpid()
  logging.debug("My pid: %d\n", pid)

  # Notify the helper that we have created the new namespace, and we need
  # it to set our uid/gid map
  logging.debug("Waiting for helper to set my uid/gid map")
  os.write(write_fd, "#")

  # Wait for the helper to finish setting our uid/gid map
  os.read(read_fd, 1)
  logging.debug("Helper has finished setting my uid/gid map")

  # ---------------------------------------------------------------------
  #                     Create Mount Namespace
  # ---------------------------------------------------------------------
  err = glibc.unshare(glibc.CLONE_NEWNS)
  if err != 0:
    logging.error('Failed to unshare mount namespace')

  null_ptr = ctypes.POINTER(ctypes.c_char)()
  for bind_spec in binds:
    if isinstance(bind_spec, (list, tuple)):
      source, dest = bind_spec
    elif ':' in bind_spec:
      source, dest = bind_spec.split(':')
    else:
      source = bind_spec
      dest = bind_spec

    dest = dest.lstrip('/')
    rootfs_dest = os.path.join(rootfs, dest)
    logging.debug('Binding: %s -> %s', source, rootfs_dest)
    if source != 'tmpfs':
      assert os.path.exists(source),\
          "source directory to bind does not exit {}".format(source)

    # Create the mountpoint if it is not already in the rootfs
    if os.path.isdir(source):
      make_sure_is_dir(rootfs_dest, source)
    else:
      make_sure_is_file(rootfs_dest, source)

    if source.lstrip('/') == 'proc':
      # NOTE(josh): user isn't allowed to mount proc without MS_REC, see
      # https://stackoverflow.com/a/23435317
      # !! special filesystem type for /dev/pts
      result = glibc.mount(source, rootfs_dest, "proc",
                           glibc.MS_REC | glibc.MS_BIND, null_ptr)
    elif source == 'tmpfs':  # !!
      result = glibc.mount(source, rootfs_dest, "tmpfs", 0, "size=100000")
    else:
      result = glibc.mount(source, rootfs_dest, null_ptr, glibc.MS_REC | glibc.MS_BIND,
                           null_ptr)
    if result == -1:
      err = ctypes.get_errno()
      logging.warn('Failed to mount %s -> %s [%s](%d) %s',
                   source, rootfs_dest, errno.errorcode.get(err, '??'), err,
                   os.strerror(err))

  # ---------------------------------------------------------------------
  #                             Chroot
  # ---------------------------------------------------------------------

  # Now chroot into the desired directory
  err = glibc.chroot(rootfs)
  if err != 0:
    logging.error("Failed to chroot")
    raise OSError(err, "Failed to chroot", rootfs)

  # Set the cwd
  os.chdir(cwd)

  # Now drop admin in our namespace
  err = glibc.setresuid(identity[0], identity[0], identity[0])
  if err != 0:
    logging.error("Failed to set uid")


  if identity[1] != os.getgid() or identity[1] != os.getegid():  # !!
    err = glibc.setresgid(identity[1], identity[1], identity[1])
    if err:
      logging.error("Failed to set gid\n")


def set_userns_idmap(chroot_pid):
  """Writes uid/gid maps for the chroot process."""
  uid = os.getuid()
  gid = os.getgid()
  username = pwd.getpwuid(uid)[0]

  # $ cat /proc/$$/uid_map
  #       0      67943          1
  # $ cat /proc/$$/gid_map
  #       0       5000          1
  # why EPERM? http://man7.org/linux/man-pages/man7/user_namespaces.7.html
  #open('/proc/%d/uid_map' % chroot_pid, 'w').write('0 %d 1\n' % (uid,))  # OK.
  #open('/proc/%d/uid_map' % chroot_pid, 'w').write('0 %d 1\n%d %d 1\n' % (uid, uid, uid))  # Fails: EINVAL (Invalid argument).
  #open('/proc/%d/uid_map' % chroot_pid, 'w').write('0 %d 1\n101 %d 1\n' % (uid, uid + 1))  # Fails: EPERM (Operation not permitted).
  open('/proc/%d/uid_map' % chroot_pid, 'w').write('%d %d 1\n' % (uid, uid))  # OK.
  # !! why groups=65534(nogroup),65534(nogroup),65534(nogroup)?
  setgroups_path = '/proc/{}/setgroups'.format(chroot_pid)
  with open(setgroups_path, 'wb') as setgroups:
    logging.debug("Writing : %s (fd=%d)\n", setgroups_path, setgroups.fileno())
    # NOTE(josh): was previously "deny", but apt-get calls this so we must
    # allow it if we want to use apt-get. Look into this more.
    setgroups.write("deny\n")  # !!
  print 'SETGR: %r' % open('/proc/%d/setgroups' % chroot_pid).read()
  print 'GID: %r' % [os.getgid(), os.getegid()]
  f = open('/proc/%d/gid_map' % chroot_pid, 'w'); f.write('%d %d 1\n' % (gid, gid)); f.close()  # !! Why: Fails: EPERM (Operation not permitted).


def umain(rootfs, binds=None, identity=None, cwd=None):
  """Fork off a helper subprocess, enter the chroot jail. Wait for the helper
     to  call the setuid-root helper programs and configure the uid map of the
     jail, then return."""

  #for idmap_bin in ['newuidmap', 'newgidmap']:
  #  assert os.path.exists('/usr/bin/{}'.format(idmap_bin)), \
  #      "Missing required binary '{}'".format(idmap_bin)

  # Pipes used to synchronize between the helper process and the chroot
  # process. Could also use eventfd, but this is simpler because python
  # already has os.pipe()
  helper_read_fd, primary_write_fd = os.pipe()
  primary_read_fd, helper_write_fd = os.pipe()

  parent_pid = os.getpid()
  child_pid = os.fork()

  if child_pid == 0:
    # Wait for the primary to create its new namespace
    os.read(helper_read_fd, 1)

    # Set the uid/gid map using the setuid helper programs
    set_userns_idmap(parent_pid)
    # Inform the primary that we have finished setting its uid/gid map.
    os.write(helper_write_fd, '#')

    # NOTE(josh): using sys.exit() will interfere with the interpreter in the
    # parent process.
    # see: https://docs.python.org/3/library/os.html#os._exit
    os._exit(0)  # pylint: disable=protected-access
  else:
    enter(primary_read_fd, primary_write_fd, rootfs, binds, identity, cwd)


# ---

def main(sys_argv):
  format_str = '%(levelname)-4s %(filename)s[%(lineno)-3s] : %(message)s'
  logging.basicConfig(level=logging.DEBUG,
                      format=format_str,
                      datefmt='%Y-%m-%d %H:%M:%S',
                      filemode='w')

  rootfs = sys_argv[1]
  argv = ['id'];  exbin = '/usr/bin/id'
  #argv = ['bash']; exbin = '/bin/bash'
  env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}
  cwd = '/'  # !!
  binds = ['/proc', '/dev/pts', 'tmpfs:/var/tmp']
  #config['binds'].extend(('/proc', '/dev/pts'))  # !!
  identity = (os.getuid(), os.getgid())  # !!

  umain(rootfs=rootfs, binds=binds, identity=identity, cwd=cwd)
  os.execve(exbin, argv, env)
  logging.error("Failed to start a shell")
  return 1


if __name__ == '__main__':
  sys.exit(main(sys.argv))
