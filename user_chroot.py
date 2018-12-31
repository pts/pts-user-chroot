#! /usr/bin/python
#
# user_chroot.py: doing chroot while
# by pts@fazekas.hu at Mon Dec 31 13:57:19 CET 2018
#
# Based on: git clone https://github.com/cheshirekow/uchroot && cd uchroot && git checkout 4b3cf28765e17f9b6de74fcedfc78a5ace26bb77
#

import argparse
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


def write_setgroups(pid):
  setgroups_path = '/proc/{}/setgroups'.format(pid)
  with open(setgroups_path, 'wb') as setgroups:
    logging.debug("Writing : %s (fd=%d)\n", setgroups_path, setgroups.fileno())
    # NOTE(josh): was previously "deny", but apt-get calls this so we must
    # allow it if we want to use apt-get. Look into this more.
    setgroups.write("deny\n")  # !!


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


def enter(read_fd, write_fd, rootfs=None, binds=None, qemu=None, identity=None,
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

  if qemu:
    dest = qemu.lstrip('/')
    rootfs_dest = os.path.join(rootfs, dest)
    make_sure_is_dir(os.path.dirname(rootfs_dest), qemu)
    logging.debug("Installing %s", qemu)
    with open(rootfs_dest, 'wb') as outfile:
      with open(qemu, 'rb') as infile:
        chunk = infile.read(1024 * 4)
        while chunk:
          outfile.write(chunk)
          chunk = infile.read(1024 * 4)

    os.chmod(rootfs_dest, 0755)

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
  write_setgroups(chroot_pid)
  print 'SETGR: %r' % open('/proc/%d/setgroups' % chroot_pid).read()
  print 'GID: %r' % [os.getgid(), os.getegid()]
  f = open('/proc/%d/gid_map' % chroot_pid, 'w'); f.write('%d %d 1\n' % (gid, gid)); f.close()  # !! Why: Fails: EPERM (Operation not permitted).


def umain(rootfs, binds=None, qemu=None, identity=None, cwd=None):
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
    enter(primary_read_fd, primary_write_fd, rootfs, binds, qemu,
          identity, cwd)


def process_environment(env_dict):
  """Given an environment dictionary, merge any lists with pathsep and return
     the new dictionary."""
  out_dict = {}
  for key, value in env_dict.iteritems():
    if isinstance(value, list):
      out_dict[key] = ':'.join(value)
    elif isinstance(value, (str, unicode)):
      out_dict[key] = value
    else:
      out_dict[key] = str(value)
  return out_dict


# exec defaults
#DEFAULT_BIN = '/bin/bash'
#DEFAULT_ARGV = ['bash']
DEFAULT_BIN = '/usr/bin/id'
DEFAULT_ARGV = ['id']  # !!
DEFAULT_PATH = ['/usr/sbin', '/usr/bin', '/sbin', '/bin']


def serialize(obj):
  """
  Return a serializable representation of the object. If the object has an
  `as_dict` method, then it will call and return the output of that method.
  Otherwise return the object itself.
  """
  if hasattr(obj, 'as_dict'):
    fun = getattr(obj, 'as_dict')
    if callable(fun):
      return fun()

  return obj


class ConfigObject(object):
  """
  Provides simple serialization to a dictionary based on the assumption that
  all args in the __init__() function are fields of this object.
  """

  @classmethod
  def get_field_names(cls):
    """
    The order of fields in the tuple representation is the same as the order
    of the fields in the __init__ function
    """

    # NOTE(josh): args[0] is `self`
    return inspect.getargspec(cls.__init__).args[1:]

  def as_dict(self):
    """
    Return a dictionary mapping field names to their values only for fields
    specified in the constructor
    """
    return {field: serialize(getattr(self, field))
            for field in self.get_field_names()}


def get_default(obj, default):
  """
  If obj is not `None` then return it. Otherwise return default.
  """
  if obj is None:
    return default

  return obj


class Exec(ConfigObject):
  """
  Simple object to hold together the path, argument vector, and environment
  of an exec call.
  """

  def __init__(self, exbin=None, argv=None, env=None, **_):
    if exbin:
      self.exbin = exbin
      if not argv:
        argv = [exbin.split('/')[-1]]
    else:
      self.exbin = DEFAULT_BIN

    if argv:
      self.argv = argv
    else:
      self.argv = DEFAULT_ARGV

    if env is not None:
      self.env = process_environment(env)
    else:
      self.env = process_environment(dict(PATH=DEFAULT_PATH))

  def __call__(self):
    logging.debug('Executing %s', self.exbin)
    return os.execve(self.exbin, self.argv, self.env)

  def subprocess(self, preexec_fn=None):
    logging.debug('Executing %s', self.exbin)
    return subprocess.call(self.argv, executable=self.exbin, env=self.env,
                           preexec_fn=preexec_fn)


class Main(ConfigObject):
  """
  Simple bind for subprocess prexec_fn.
  """

  def __init__(self,
               rootfs=None,
               binds=None,
               qemu=None,
               identity=None,
               cwd=None,
               **_):
    self.rootfs = rootfs
    self.binds = get_default(binds, [])
    self.qemu = qemu
    self.identity = get_default(identity, (0, 0))

    uid = os.getuid()
    username = pwd.getpwuid(uid)[0]
    self.cwd = get_default(cwd, '/')

  def __call__(self):
    umain(**self.as_dict())


def parse_config(config_path):
  """
  Open the config file as json, strip comments, load it and return the
  resulting dictionary.
  """

  stripped_json_str = ''

  # NOTE(josh): strip comments out of the config file.
  with open(config_path, 'rb') as infile:
    for line in infile:
      line = re.sub('//.*$', '', line).rstrip()
      if line:
        stripped_json_str += line
        stripped_json_str += '\n'

  try:
    return json.loads(stripped_json_str)
  except (ValueError, KeyError):
    logging.error('Failed to decode json:\n%s', stripped_json_str)
    raise


# ---

def parse_bool(string):
  if string.lower() in ('y', 'yes', 't', 'true', '1', 'yup', 'yeah', 'yada'):
    return True
  elif string.lower() in ('n', 'no', 'f', 'false', '0', 'nope', 'nah', 'nada'):
    return False

  logging.warn("Ambiguous truthiness of string '%s' evalutes to 'FALSE'",
               string)
  return False


def main():
  format_str = '%(levelname)-4s %(filename)s[%(lineno)-3s] : %(message)s'
  logging.basicConfig(level=logging.INFO,
                      format=format_str,
                      datefmt='%Y-%m-%d %H:%M:%S',
                      filemode='w')

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--dump-config', action='store_true',
                      help='Dump default config and exit')

  config = Main().as_dict()  # !!
  config.update(Exec().as_dict())  # !!
  config = {'argv': ['id'], 'binds': [], 'env': {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, 'exbin': '/usr/bin/id', 'qemu': None, 'cwd': '/', 'rootfs': None}
  config['binds'].extend(('/proc', '/dev/pts', 'tmpfs:/var/tmp'))  # !!
  #config['binds'].extend(('/proc', '/dev/pts'))  # !!
  config['identity'] = (os.getuid(), os.getgid())  # !!

  for key, value in config.items():
    if key == 'rootfs':
      continue
    # NOTE(josh): argparse store_true isn't what we want here because we want
    # to distinguish between "not specified" = "default" and "specified"
    elif isinstance(value, bool):
      parser.add_argument('--' + key.replace('_', '-'), nargs='?', default=None,
                          const=True, type=parse_bool, help='HELP')
    elif isinstance(value, (str, unicode, int, float)) or value is None:
      parser.add_argument('--' + key.replace('_', '-'))
    # NOTE(josh): argparse behavior is that if the flag is not specified on
    # the command line the value will be None, whereas if it's specified with
    # no arguments then the value will be an empty list. This exactly what we
    # want since we can ignore `None` values.
    elif isinstance(value, (list, tuple)):
      if value:
        argtype = type(value[0])
      else:
        argtype = None
      parser.add_argument('--' + key.replace('_', '-'), nargs='*',
                          type=argtype, help='HELP')

  parser.add_argument('rootfs', nargs='?',
                      help='path of the rootfs to enter')
  parser.add_argument('remainder', metavar='ARGV',
                      nargs=argparse.REMAINDER,
                      help='command and arguments')
  args = parser.parse_args()

  if args.dump_config:
    dump_config(sys.stdout)
    sys.exit(0)

  logging.getLogger().setLevel(getattr(logging, 'DEBUG'))

  if args.remainder:
    if args.argv is None:
      args.argv = []
    args.argv.extend(args.remainder)

  for key, value in vars(args).items():
    if value is not None and key in config:
      config[key] = value

  knownkeys = Main.get_field_names() + Exec.get_field_names()
  unknownkeys = []
  for key in config:
    if key.startswith('_'):
      continue

    if key in knownkeys:
      continue

    unknownkeys.append(key)

  if unknownkeys:
    logging.warn("Unrecognized config variables: %s", ", ".join(unknownkeys))

  mainobj = Main(**config)
  execobj = Exec(**config)

  # enter the jail
  mainobj()
  # and start the requested program
  execobj()
  logging.error("Failed to start a shell")
  return 1


if __name__ == '__main__':
  sys.exit(main())
