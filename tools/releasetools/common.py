# Copyright (C) 2008 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import errno
import getopt
import getpass
import imp
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import pexpect
import string

try:
  from hashlib import sha1 as sha1
except ImportError:
  from sha import sha as sha1

# missing in Python 2.4 and before
if not hasattr(os, "SEEK_SET"):
  os.SEEK_SET = 0

class Options(object): pass
OPTIONS = Options()
OPTIONS.search_path = "out/host/linux-x86"
OPTIONS.verbose = False
OPTIONS.tempfiles = []
OPTIONS.device_specific = None
OPTIONS.extras = {}
OPTIONS.info_dict = None
OPTIONS.hab_sign = False
OPTIONS.cst_path = "motorola/hab_cst_client/apk"
OPTIONS.user = os.environ["USER"]
OPTIONS.system_type = "yaffs"
OPTIONS.userdata_type = "yaffs"


# Values for "certificate" in apkcerts that mean special things.
SPECIAL_CERT_STRINGS = ("PRESIGNED", "EXTERNAL")


class ExternalError(RuntimeError): pass


def Run(args, **kwargs):
  """Create and return a subprocess.Popen object, printing the command
  line on the terminal if -v was specified."""
  if OPTIONS.verbose:
    print "  running: ", " ".join(args)
  return subprocess.Popen(args, **kwargs)

def RunExpect(args, **kwargs):
  cmd = string.join(args)
  if OPTIONS.verbose:
    print " running w/pexpect: ", cmd
  return pexpect.spawn(cmd, **kwargs)

def CloseInheritedPipes():
  """ Gmake in MAC OS has file descriptor (PIPE) leak. We close those fds
  before doing other work."""
  if platform.system() != "Darwin":
    return
  for d in range(3, 1025):
    try:
      stat = os.fstat(d)
      if stat is not None:
        pipebit = stat[0] & 0x1000
        if pipebit != 0:
          os.close(d)
    except OSError:
      pass


def LoadInfoDict(zip):
  """Read and parse the META/misc_info.txt key/value pairs from the
  input target files and return a dict."""

  d = {}
  try:
    for line in zip.read("META/misc_info.txt").split("\n"):
      line = line.strip()
      if not line or line.startswith("#"): continue
      k, v = line.split("=", 1)
      d[k] = v
  except KeyError:
    # ok if misc_info.txt doesn't exist
    pass

  # backwards compatibility: These values used to be in their own
  # files.  Look for them, in case we're processing an old
  # target_files zip.

  if "mkyaffs2_extra_flags" not in d:
    try:
      d["mkyaffs2_extra_flags"] = zip.read("META/mkyaffs2-extra-flags.txt").strip()
    except KeyError:
      # ok if flags don't exist
      pass

  if "recovery_api_version" not in d:
    try:
      d["recovery_api_version"] = zip.read("META/recovery-api-version.txt").strip()
    except KeyError:
      print "WARNING: recovery-api-version.txt not found. Hardcoding the Value to 3!!"
      d["recovery_api_version"] = "3"
      pass

  if "tool_extensions" not in d:
    try:
      d["tool_extensions"] = zip.read("META/tool-extensions.txt").strip()
    except KeyError:
      # ok if extensions don't exist
      pass

  try:
    data = zip.read("META/imagesizes.txt")
    for line in data.split("\n"):
      if not line: continue
      name, value = line.split(" ", 1)
      if not value: continue
      if name == "blocksize":
        d[name] = value
      else:
        d[name + "_size"] = value
  except KeyError:
    pass

  def makeint(key):
    if key in d:
      d[key] = int(d[key], 0)

  makeint("recovery_api_version")
  makeint("blocksize")
  makeint("system_size")
  makeint("userdata_size")
  makeint("recovery_size")
  makeint("boot_size")
# BEGIN Motorola, w20500, 9/30/2011, IKMAIN-27093/Core apps built from source code to be made deletable
  makeint("preinstall_size")
# END IKMAIN-27093
  d["fstab"] = LoadRecoveryFSTab(zip)
  return d

def LoadRecoveryFSTab(zip):
  class Partition(object):
    pass

  for fstab in ["RECOVERY/RAMDISK/etc/recovery.fstab", "FSTAB/recovery.fstab"]:
    try:
      data = zip.read(fstab)
      break
    except KeyError:
      pass
  else:
    print "Warning: could not find RECOVERY/RAMDISK/etc/recovery.fstab in %s." % zip

  d = {}
  for line in data.split("\n"):
    line = line.strip()
    if not line or line.startswith("#"): continue
    pieces = line.split()
    if not (3 <= len(pieces)):
      raise ValueError("malformed recovery.fstab line: \"%s\"" % (line,))

    p = Partition()
    p.mount_point = pieces[0]
    p.fs_type = pieces[1]
    p.device = pieces[2]
    p.length = 0
    options = None
    if len(pieces) >= 4:
      if pieces[3].startswith("/"):
        p.device2 = pieces[3]
        if len(pieces) >= 5:
          options = pieces[4]
      else:
        p.device2 = None
        options = pieces[3]
    else:
      p.device2 = None

    if options:
      options = options.split(",")
      for i in options:
        if i.startswith("length="):
          p.length = int(i[7:])
        else:
          print "%s: unknown option \"%s\"" % (p.mount_point, i)

    d[p.mount_point] = p
  return d


def DumpInfoDict(d):
  for k, v in sorted(d.items()):
    print "%-25s = (%s) %s" % (k, type(v).__name__, v)

def BuildBootableImage(sourcedir):
  """Take a kernel, cmdline, and ramdisk directory from the input (in
  'sourcedir'), and turn them into a boot image.  Return the image
  data, or None if sourcedir does not appear to contains files for
  building the requested image."""

  if (not os.access(os.path.join(sourcedir, "RAMDISK"), os.F_OK) or
      not os.access(os.path.join(sourcedir, "kernel"), os.F_OK)):
    return None

  ramdisk_img = tempfile.NamedTemporaryFile()
  img = tempfile.NamedTemporaryFile()

  p1 = Run(["mkbootfs", os.path.join(sourcedir, "RAMDISK")],
           stdout=subprocess.PIPE)
  p2 = Run(["minigzip"],
           stdin=p1.stdout, stdout=ramdisk_img.file.fileno())

  p2.wait()
  p1.wait()
  assert p1.returncode == 0, "mkbootfs of %s ramdisk failed" % (targetname,)
  assert p2.returncode == 0, "minigzip of %s ramdisk failed" % (targetname,)

  cmd = ["mkbootimg", "--kernel", os.path.join(sourcedir, "kernel")]

  fn = os.path.join(sourcedir, "cmdline")
  if os.access(fn, os.F_OK):
    cmd.append("--cmdline")
    cmd.append(open(fn).read().rstrip("\n"))

  fn = os.path.join(sourcedir, "base")
  if os.access(fn, os.F_OK):
    cmd.append("--base")
    cmd.append(open(fn).read().rstrip("\n"))

  fn = os.path.join(sourcedir, "pagesize")
  if os.access(fn, os.F_OK):
    cmd.append("--pagesize")
    cmd.append(open(fn).read().rstrip("\n"))

  cmd.extend(["--ramdisk", ramdisk_img.name,
              "--output", img.name])

  p = Run(cmd, stdout=subprocess.PIPE)
  p.communicate()
  assert p.returncode == 0, "mkbootimg of %s image failed" % (
      os.path.basename(sourcedir),)

  img.seek(os.SEEK_SET, 0)
  data = img.read()

  ramdisk_img.close()
  img.close()

  return data


def GetBootableImage(name, prebuilt_name, unpack_dir, tree_subdir):
  """Return a File object (with name 'name') with the desired bootable
  image.  Look for it in 'unpack_dir'/BOOTABLE_IMAGES under the name
  'prebuilt_name', otherwise construct it from the source files in
  'unpack_dir'/'tree_subdir'."""

  prebuilt_path = os.path.join(unpack_dir, "BOOTABLE_IMAGES", prebuilt_name)
  if os.path.exists(prebuilt_path):
    print "using prebuilt %s..." % (prebuilt_name,)
    return File.FromLocalFile(name, prebuilt_path)
  else:
    print "building image from target_files %s..." % (tree_subdir,)
    return File(name, BuildBootableImage(os.path.join(unpack_dir, tree_subdir)))


def UnzipTemp(filename, pattern=None):
  """Unzip the given archive into a temporary directory and return the name.

  If filename is of the form "foo.zip+bar.zip", unzip foo.zip into a
  temp dir, then unzip bar.zip into that_dir/BOOTABLE_IMAGES.

  Returns (tempdir, zipobj) where zipobj is a zipfile.ZipFile (of the
  main file), open for reading.
  """

  tmp = tempfile.mkdtemp(prefix="targetfiles-")
  OPTIONS.tempfiles.append(tmp)

  def unzip_to_dir(filename, dirname):
    cmd = ["unzip", "-o", "-q", filename, "-d", dirname]
    if pattern is not None:
      cmd.append(pattern)
    p = Run(cmd, stdout=subprocess.PIPE)
    p.communicate()
    if p.returncode != 0:
      raise ExternalError("failed to unzip input target-files \"%s\"" %
                          (filename,))

  m = re.match(r"^(.*[.]zip)\+(.*[.]zip)$", filename, re.IGNORECASE)
  if m:
    unzip_to_dir(m.group(1), tmp)
    unzip_to_dir(m.group(2), os.path.join(tmp, "BOOTABLE_IMAGES"))
    filename = m.group(1)
  else:
    unzip_to_dir(filename, tmp)

  return tmp, zipfile.ZipFile(filename, "r")


def GetKeyPasswords(keylist):
  """Given a list of keys, prompt the user to enter passwords for
  those which require them.  Return a {key: password} dict.  password
  will be None if the key has no password."""

  no_passwords = []
  need_passwords = []
  if not OPTIONS.hab_sign:
    devnull = open("/dev/null", "w+b")
    for k in sorted(keylist):
      # We don't need a password for things that aren't really keys.
      if k in SPECIAL_CERT_STRINGS:
        no_passwords.append(k)
        continue

      p = Run(["openssl", "pkcs8", "-in", k+".pk8",
               "-inform", "DER", "-nocrypt"],
              stdin=devnull.fileno(),
              stdout=devnull.fileno(),
              stderr=subprocess.STDOUT)
      p.communicate()
      if p.returncode == 0:
        no_passwords.append(k)
      else:
        need_passwords.append(k)
    devnull.close()

    key_passwords = PasswordManager().GetPasswords(need_passwords)
    key_passwords.update(dict.fromkeys(no_passwords, None))
  else:
    """In case of automated signing we do not need to collect credentials"""
    if os.environ.get("CST_AUTO_SIGN") == '1' and \
       os.path.isfile(OPTIONS.cst_path + "/config/hab_service.config"):
      passwd=""
    else:
      passwd=getpass.getpass("Enter Motorola OneIT password for coreID ( %s ) > " % OPTIONS.user)

    for k in sorted(keylist):
      # An empty-string key is used to mean don't re-sign this package.
      # Obviously we don't need a password for this non-key.
      if not k:
        no_passwords.append(k)
        continue
      """ for all packages that need HAB signing, will require password """
      need_passwords.append(k)
      
      key_passwords = dict.fromkeys(need_passwords, passwd) 
      key_passwords.update(dict.fromkeys(no_passwords, None))

  return key_passwords


def SignFile(input_name, output_name, key, password, align=None,
             whole_file=False):
  """Sign the input_name zip/jar/apk, producing output_name.  Use the
  given key and password (the latter may be None if the key does not
  have a password.

  If align is an integer > 1, zipalign is run to align stored files in
  the output zip on 'align'-byte boundaries.

  If whole_file is true, use the "-w" option to SignApk to embed a
  signature that covers the whole file in the archive comment of the
  zip file.
  """

  if align == 0 or align == 1:
    align = None

  if align:
    temp = tempfile.NamedTemporaryFile()
    sign_name = temp.name
  else:
    sign_name = output_name

  if not OPTIONS.hab_sign:
    cmd = ["java", "-Xmx2048m", "-jar",
           os.path.join(OPTIONS.search_path, "framework", "signapk.jar")]

    if whole_file:
      cmd.append("-w")

    cmd.extend([key + ".x509.pem", key + ".pk8",
                input_name, sign_name])

    p = Run(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    if password is not None:
      password += "\n"
    p.communicate(password)
    if p.returncode != 0:
      raise ExternalError("signapk.jar failed: return code %s" % (p.returncode,))
  else:
    userid = OPTIONS.user
    env = os.environ
    cwd = os.getcwd()
    env["CST_CLIENT_INSTALL_PATH"] = OPTIONS.cst_path

    c = RunExpect(["java",
                   "-Xmx2048m",
                   "-jar",
                   os.path.join(OPTIONS.cst_path, "bin", "signapk.jar "),
                   key + ".x509.crt",
                   "HAB",
                   input_name,
                   sign_name],
                  env=env,
                  cwd=cwd)

    if OPTIONS.verbose:
      """ only read output from signapk.jar """
      c.logfile_read = sys.stdout

    """In case of automated signing signapk.jar doesn't request userid & pswd"""
    if os.environ.get("CST_AUTO_SIGN") != '1' or \
       not os.path.isfile(OPTIONS.cst_path + "/config/hab_service.config"):
      rcvd = c.expect(['user ID:',pexpect.EOF,pexpect.TIMEOUT], timeout=15)
      if rcvd == 0:
        userid += "\n"
        c.send(userid)
      elif rcvd == 1:
        print c.before
        raise ExternalError("signapk.jar failed.")
      elif rcvd == 2:
        raise ExternalError("timed out waiting for userID prompt from signapk.jar!")
      rcvd = c.expect(['Password:',pexpect.EOF,pexpect.TIMEOUT], timeout=15)
      if rcvd == 0:
        password += "\n"
        c.setecho(False)
        c.send(password)
        c.setecho(True)
        c.logfile_read = sys.stdout
      elif rcvd == 1:
        print c.before
        raise ExternalError("signapk.jar failed.")
      elif rcvd == 2:
        raise ExternalError("timed out waiting for password prompt from signapk.jar!")

    rcvd = c.expect([pexpect.EOF,pexpect.TIMEOUT], timeout=60)
    if rcvd == 0:
      """ always call close() before trying to read exitstatus """
      c.close()
      if c.exitstatus != 0:
        raise ExternalError("signapk.jar failed with an error.")
    elif rcvd == 1:
      raise ExternalError("signapk.jar timeout waiting for CST response.")

  if align:
    p = Run(["zipalign", "-f", str(align), sign_name, output_name])
    p.communicate()
    if p.returncode != 0:
      raise ExternalError("zipalign failed: return code %s" % (p.returncode,))
    temp.close()


def CheckSize(data, target, info_dict):
  """Check the data string passed against the max size limit, if
  any, for the given target.  Raise exception if the data is too big.
  Print a warning if the data is nearing the maximum size."""

  if target.endswith(".img"): target = target[:-4]
  mount_point = "/" + target

  if info_dict["fstab"]:
    if mount_point == "/userdata": mount_point = "/data"
    p = info_dict["fstab"][mount_point]
    fs_type = p.fs_type
    limit = info_dict.get(p.device + "_size", None)
  if not fs_type or not limit: return

  if fs_type == "yaffs2":
    # image size should be increased by 1/64th to account for the
    # spare area (64 bytes per 2k page)
    limit = limit / 2048 * (2048+64)
    size = len(data)
    pct = float(size) * 100.0 / limit
    msg = "%s size (%d) is %.2f%% of limit (%d)" % (target, size, pct, limit)
    if pct >= 99.0:
      raise ExternalError(msg)
    elif pct >= 95.0:
      print
      print "  WARNING: ", msg
      print
    elif OPTIONS.verbose:
      print "  ", msg


def ReadApkCerts(tf_zip):
  """Given a target_files ZipFile, parse the META/apkcerts.txt file
  and return a {package: cert} dict."""
  certmap = {}
  for line in tf_zip.read("META/apkcerts.txt").split("\n"):
    line = line.strip()
    if not line: continue
    m = re.match(r'^name="(.*)"\s+certificate="(.*)"\s+'
                 r'private_key="(.*)"$', line)
    if m:
      name, cert, privkey = m.groups()
      if cert in SPECIAL_CERT_STRINGS and not privkey:
        certmap[name] = cert
      elif (cert.endswith(".x509.pem") and
            privkey.endswith(".pk8") and
            cert[:-9] == privkey[:-4]):
        certmap[name] = cert[:-9]
      else:
        raise ValueError("failed to parse line from apkcerts.txt:\n" + line)
  return certmap


COMMON_DOCSTRING = """
  -p  (--path)  <dir>
      Prepend <dir>/bin to the list of places to search for binaries
      run by this script, and expect to find jars in <dir>/framework.

  -s  (--device_specific) <file>
      Path to the python module containing device-specific
      releasetools code.

  -v  (--verbose)
      Show command lines being executed.

  -m  (--hab_sign)
      Alternatively sign APK's using HAB Signing Server

  -c  (--cst_path)
      Path to HAB code signing tools installation, defaults to
      motorola/hab_cst_client/apk. Only used with --hab_sign option.

  -u  (--user)
      Specify UserID to use when using HAB signing option. The userID
      must be a Motorola CoreID. Defaults to system login userID.

  -h  (--help)
      Display this usage message and exit.
"""

def Usage(docstring):
  print docstring.rstrip("\n")
  print COMMON_DOCSTRING


def ParseOptions(argv,
                 docstring,
                 extra_opts="", extra_long_opts=(),
                 extra_option_handler=None):
  """Parse the options in argv and return any arguments that aren't
  flags.  docstring is the calling module's docstring, to be displayed
  for errors and -h.  extra_opts and extra_long_opts are for flags
  defined by the caller, which are processed by passing them to
  extra_option_handler."""

  try:
    opts, args = getopt.getopt(
        argv, "hvp:s:" + extra_opts,
        ["help", "verbose", "path=", "device_specific=", "extra=", "hab_sign", "cst_path=", "user=", "system_type=", "userdata_type="] +
          list(extra_long_opts))
  except getopt.GetoptError, err:
    Usage(docstring)
    print "**", str(err), "**"
    sys.exit(2)

  path_specified = False

  filesystem_types = ["yaffs", "ext2", "ext3"]

  for o, a in opts:
    if o in ("-h", "--help"):
      Usage(docstring)
      sys.exit()
    elif o in ("-v", "--verbose"):
      OPTIONS.verbose = True
    elif o in ("-p", "--path"):
      OPTIONS.search_path = a
    elif o in ("-s", "--device_specific"):
      OPTIONS.device_specific = a
    elif o in ("-x", "--extra"):
      key, value = a.split("=", 1)
      OPTIONS.extras[key] = value
    elif o in ("-hab", "--hab_sign"):
      OPTIONS.hab_sign = True
    elif o in ("-c", "--cst_path"):
      OPTIONS.cst_path = a
    elif o in ("-u", "--user"):
      OPTIONS.user = a
    elif o == "--system_type":
      assert a in filesystem_types, "unknown system fs type \"%s\"" % (a,)
      OPTIONS.system_type = a
    elif o == "--userdata_type":
      assert a in filesystem_types, "unknown userdata fs type \"%s\"" % (a,)
      OPTIONS.userdata_type = a
    else:
      if extra_option_handler is None or not extra_option_handler(o, a):
        assert False, "unknown option \"%s\"" % (o,)

  os.environ["PATH"] = (os.path.join(OPTIONS.search_path, "bin") +
                        os.pathsep + os.environ["PATH"])

  return args


def Cleanup():
  for i in OPTIONS.tempfiles:
    if os.path.isdir(i):
      shutil.rmtree(i)
    else:
      os.remove(i)


class PasswordManager(object):
  def __init__(self):
    self.editor = os.getenv("EDITOR", None)
    self.pwfile = os.getenv("ANDROID_PW_FILE", None)

  def GetPasswords(self, items):
    """Get passwords corresponding to each string in 'items',
    returning a dict.  (The dict may have keys in addition to the
    values in 'items'.)

    Uses the passwords in $ANDROID_PW_FILE if available, letting the
    user edit that file to add more needed passwords.  If no editor is
    available, or $ANDROID_PW_FILE isn't define, prompts the user
    interactively in the ordinary way.
    """

    current = self.ReadFile()

    first = True
    while True:
      missing = []
      for i in items:
        if i not in current or not current[i]:
          missing.append(i)
      # Are all the passwords already in the file?
      if not missing: return current

      for i in missing:
        current[i] = ""

      if not first:
        print "key file %s still missing some passwords." % (self.pwfile,)
        answer = raw_input("try to edit again? [y]> ").strip()
        if answer and answer[0] not in 'yY':
          raise RuntimeError("key passwords unavailable")
      first = False

      current = self.UpdateAndReadFile(current)

  def PromptResult(self, current):
    """Prompt the user to enter a value (password) for each key in
    'current' whose value is fales.  Returns a new dict with all the
    values.
    """
    result = {}
    for k, v in sorted(current.iteritems()):
      if v:
        result[k] = v
      else:
        while True:
          if sys.stdin.isatty():
            result[k] = getpass.getpass("Enter password for %s key> "
                                      % (k,)).strip()
          else:
            #result[k] = sys.stdin.readline().rstrip()
            result[k] = "calgaryRocks"
          if result[k]: break
    return result

  def UpdateAndReadFile(self, current):
    if not self.editor or not self.pwfile:
      return self.PromptResult(current)

    f = open(self.pwfile, "w")
    os.chmod(self.pwfile, 0600)
    f.write("# Enter key passwords between the [[[ ]]] brackets.\n")
    f.write("# (Additional spaces are harmless.)\n\n")

    first_line = None
    sorted = [(not v, k, v) for (k, v) in current.iteritems()]
    sorted.sort()
    for i, (_, k, v) in enumerate(sorted):
      f.write("[[[  %s  ]]] %s\n" % (v, k))
      if not v and first_line is None:
        # position cursor on first line with no password.
        first_line = i + 4
    f.close()

    p = Run([self.editor, "+%d" % (first_line,), self.pwfile])
    _, _ = p.communicate()

    return self.ReadFile()

  def ReadFile(self):
    result = {}
    if self.pwfile is None: return result
    try:
      f = open(self.pwfile, "r")
      for line in f:
        line = line.strip()
        if not line or line[0] == '#': continue
        m = re.match(r"^\[\[\[\s*(.*?)\s*\]\]\]\s*(\S+)$", line)
        if not m:
          print "failed to parse password file: ", line
        else:
          result[m.group(2)] = m.group(1)
      f.close()
    except IOError, e:
      if e.errno != errno.ENOENT:
        print "error reading password file: ", str(e)
    return result


def ZipWriteStr(zip, filename, data, perms=0644):
  # use a fixed timestamp so the output is repeatable.
  zinfo = zipfile.ZipInfo(filename=filename,
                          date_time=(2009, 1, 1, 0, 0, 0))
  zinfo.compress_type = zip.compression
  zinfo.external_attr = perms << 16
  zip.writestr(zinfo, data)


class DeviceSpecificParams(object):
  module = None
  def __init__(self, **kwargs):
    """Keyword arguments to the constructor become attributes of this
    object, which is passed to all functions in the device-specific
    module."""
    for k, v in kwargs.iteritems():
      setattr(self, k, v)

    if self.module is None:
      path = OPTIONS.device_specific
      if not path: return
      try:
        if os.path.isdir(path):
          info = imp.find_module("releasetools", [path])
        else:
          d, f = os.path.split(path)
          b, x = os.path.splitext(f)
          if x == ".py":
            f = b
          info = imp.find_module(f, [d])
        self.module = imp.load_module("device_specific", *info)
      except ImportError:
        print "unable to load device-specific module; assuming none"

  def _DoCall(self, function_name, *args, **kwargs):
    """Call the named function in the device-specific module, passing
    the given args and kwargs.  The first argument to the call will be
    the DeviceSpecific object itself.  If there is no module, or the
    module does not define the function, return the value of the
    'default' kwarg (which itself defaults to None)."""
    if self.module is None or not hasattr(self.module, function_name):
      return kwargs.get("default", None)
    return getattr(self.module, function_name)(*((self,) + args), **kwargs)

  def FullOTA_Assertions(self):
    """Called after emitting the block of assertions at the top of a
    full OTA package.  Implementations can add whatever additional
    assertions they like."""
    return self._DoCall("FullOTA_Assertions")

  def FullOTA_InstallEnd(self):
    """Called at the end of full OTA installation; typically this is
    used to install the image for the device's baseband processor."""
    return self._DoCall("FullOTA_InstallEnd")

  def IncrementalOTA_Assertions(self):
    """Called after emitting the block of assertions at the top of an
    incremental OTA package.  Implementations can add whatever
    additional assertions they like."""
    return self._DoCall("IncrementalOTA_Assertions")

  def IncrementalOTA_VerifyEnd(self):
    """Called at the end of the verification phase of incremental OTA
    installation; additional checks can be placed here to abort the
    script before any changes are made."""
    return self._DoCall("IncrementalOTA_VerifyEnd")

  def IncrementalBP_VerifyEnd(self):
    return self._DoCall("IncrementalBP_VerifyEnd")

  def IncrementalOTA_InstallEnd(self):
    """Called at the end of incremental OTA installation; typically
    this is used to install the image for the device's baseband
    processor."""
    return self._DoCall("IncrementalOTA_InstallEnd")

#BEGIN Motorola,tbdc37 01/04/2012 IKCBS-2797 Move multiconfig installation at last
  def IncrementalOTA_Multiconfig_InstallEnd(self):
    """Called at the end of script generation.Multiconfig related
    apis should be added at the end of script."""
    return self._DoCall("IncrementalOTA_Multiconfig_InstallEnd")
#End Motorola,tbdc37 01/04/2012 IKCBS-2797

#BEGIN Motorola, a22338, 02/15/2011, IKSTABLEFOURV-1037 / Script changes for generating validation pkg
  def AutoValidation_VerifyEnd(self):
    return self._DoCall("AutoValidation_VerifyEnd")
#END IKSTABLEFOURV-1037
#BEGIN Motorola, tbdc37, 03/17/2011, IKCBS-1224
  def FullOTA_InstallStart(self):
    """Called at the beginning of full OTA installation; typically this is
    used to execute device specific extensions just before the start of the installation
    process... such as mounting some device-specific partitions."""
    return self._DoCall("FullOTA_InstallStart")

  def IncrementalOTA_InstallStart(self):
    """Called at the beginning of incremental OTA installation; typically this is
    used to execute device specific extensions just before the start of the installation
    process... such as mounting some device-specific partitions."""
    return self._DoCall("IncrementalOTA_InstallStart")
#END IKCBS-1224
#BEGIN Motorola, fmpr73, 03/23/2012, IKHSS6UPGR-3751
  def IncrementalBP_InstallBegin(self):
    """Called at the beginning of full OTA installation; typically to execute
    BP update before AP update"""
    return self._DoCall("IncrementalBP_InstallBegin")
#END IKHSS6UPGR-3751
#BEGIN Motorola, fmpr73, 03/23/2012, IKHSS6UPGR-3751
  def FullBP_InstallBegin(self):
    """Called at the beginning of full OTA installation; typically to execute
    BP update before AP update"""
    return self._DoCall("FullBP_InstallBegin")
#END IKHSS6UPGR-3751


class File(object):
  def __init__(self, name, data):
    self.name = name
    self.data = data
    self.size = len(data)
    self.sha1 = sha1(data).hexdigest()

  @classmethod
  def FromLocalFile(cls, name, diskname):
    f = open(diskname, "rb")
    data = f.read()
    f.close()
    return File(name, data)

  def WriteToTemp(self):
    t = tempfile.NamedTemporaryFile()
    t.write(self.data)
    t.flush()
    return t

  def AddToZip(self, z):
    ZipWriteStr(z, self.name, self.data)

DIFF_PROGRAM_BY_EXT = {
    ".gz" : "imgdiff",
    ".zip" : ["imgdiff", "-z"],
    ".jar" : ["imgdiff", "-z"],
    ".apk" : ["imgdiff", "-z"],
    ".img" : "imgdiff",
    }

class Difference(object):
  def __init__(self, tf, sf):
    self.tf = tf
    self.sf = sf
    self.patch = None

  def ComputePatch(self):
    """Compute the patch (as a string of data) needed to turn sf into
    tf.  Returns the same tuple as GetPatch()."""

    tf = self.tf
    sf = self.sf

    ext = os.path.splitext(tf.name)[1]
    diff_program = DIFF_PROGRAM_BY_EXT.get(ext, "bsdiff")

    ttemp = tf.WriteToTemp()
    stemp = sf.WriteToTemp()

    ext = os.path.splitext(tf.name)[1]

    try:
      ptemp = tempfile.NamedTemporaryFile()
      if isinstance(diff_program, list):
        cmd = copy.copy(diff_program)
      else:
        cmd = [diff_program]
      cmd.append(stemp.name)
      cmd.append(ttemp.name)
      cmd.append(ptemp.name)
      p = Run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      _, err = p.communicate()
      if err or p.returncode != 0:
        print "WARNING: failure running %s:\n%s\n" % (diff_program, err)
        return None
      diff = ptemp.read()
    finally:
      ptemp.close()
      stemp.close()
      ttemp.close()

    self.patch = diff
    return self.tf, self.sf, self.patch


  def GetPatch(self):
    """Return a tuple (target_file, source_file, patch_data).
    patch_data may be None if ComputePatch hasn't been called, or if
    computing the patch failed."""
    return self.tf, self.sf, self.patch


def ComputeDifferences(diffs):
  """Call ComputePatch on all the Difference objects in 'diffs'."""
  print len(diffs), "diffs to compute"

  # Do the largest files first, to try and reduce the long-pole effect.
  by_size = [(i.tf.size, i) for i in diffs]
  by_size.sort(reverse=True)
  by_size = [i[1] for i in by_size]

  lock = threading.Lock()
  diff_iter = iter(by_size)   # accessed under lock

  def worker():
    try:
      lock.acquire()
      for d in diff_iter:
        lock.release()
        start = time.time()
        d.ComputePatch()
        dur = time.time() - start
        lock.acquire()

        tf, sf, patch = d.GetPatch()
        if sf.name == tf.name:
          name = tf.name
        else:
          name = "%s (%s)" % (tf.name, sf.name)
        if patch is None:
          print "patching failed!                                  %s" % (name,)
        else:
          print "%8.2f sec %8d / %8d bytes (%6.2f%%) %s" % (
              dur, len(patch), tf.size, 100.0 * len(patch) / tf.size, name)
      lock.release()
    except Exception, e:
      print e
      raise

  # start worker threads; wait for them all to finish.
  threads = [threading.Thread(target=worker)
             for i in range(OPTIONS.worker_threads)]
  for th in threads:
    th.start()
  while threads:
    threads.pop().join()


# map recovery.fstab's fs_types to mount/format "partition types"
PARTITION_TYPES = { "yaffs2": "MTD", "mtd": "MTD",
                    "ext4": "EMMC", "emmc": "EMMC",
                    "ext3": "MTD" , "raw": "MTD" }

def GetTypeAndDevice(mount_point, info):
  fstab = info["fstab"]
  if fstab:
    return PARTITION_TYPES[fstab[mount_point].fs_type], fstab[mount_point].device
  else:
    return None

def CreateImageYaffs(input_path, output_image):
  p = Run(["mkyaffs2image", "-f", input_path, output_image])
  p.communicate()
  assert p.returncode == 0, "mkyaffs2image failed: " + output_image

def GetNumInodesForPath(path):
  """Return the number of inodes needed to store the filesystem rooted
  at <path>. Equivalent to: `find <path> | wc -l`"""
  num_inodes = 0
  for root, dirs, files in os.walk(path):
    num_inodes += 1 + len(files)
  return num_inodes

def GetNumBlocksForPath(path):
  """Return the number of blocks required to store the filesystem rooted
  at <path>. Equivalent to: `du -sk <path> | tail -n1 | awk '{print $1;}'`"""

  # du will report 0 size for symlinks, make sure this is a real directory
  path = os.path.realpath(path)

  p = Run(["du", "-sk", path], stdout=subprocess.PIPE)
  out, err = p.communicate()
  assert p.returncode == 0, "du failed"
  return int(out.split()[0])
# BEGIN Motorola, w20500, 9/30/2011, IKMAIN-27093/Core apps built from source code to be made deletable
# add support for creating other images except for system&data image.
def CreateImageExt2(input_path, output_image, journal=False, label=None, num_blocks=None, other_image=False):
# END IKMAIN-27093
  """Creates an ext2 image <output_image> from the files rooted at
  <input_path>. If <journal> is True, add a journal to the file system.
  If <label> is not None, it will be used as the ext label for the file
  system. If <num_blocks> is not None, it is the size of the image to
  generate in 1k blocks.
  This is the same procedure as external/genext2fs/Config.mk."""

  # add extra inodes
  num_inodes = GetNumInodesForPath(input_path)
  extra_inodes = 500
  num_inodes += extra_inodes

  # compute filesystem size in blocks
  if num_blocks is None:
    num_blocks = GetNumBlocksForPath(input_path)
    if num_blocks < 20480:
      extra_blocks = 3072
    else:
      extra_blocks = 20480
    num_blocks += extra_blocks

  # create initial image
  # BEGIN Motorola, w20500, 9/30/2011, IKMAIN-27093/Core apps built from source code to be made deletable
  # add support for creating other images except for system&data image.
  if other_image:
    img_arg='-U'
  else:
    img_arg='-a'
  p = Run(['genext2fs', img_arg, '-d', input_path, '-b', str(num_blocks),
    '-N', str(num_inodes), '-m', '0', output_image])
  # END IKMAIN-27093
  p.communicate()
  assert p.returncode == 0, "genext2fs failed: " + output_image

  # apply label if requested
  if label is not None:
    p = Run(['tune2fs', '-L', label, output_image])
    p.communicate()
    assert p.returncode == 0, "failed to set label for " + output_image

  # enable journal if requested
  if journal:
    p = Run(['tune2fs', '-j', output_image])
    p.communicate()
    assert p.returncode == 0, "failed to create journal for " + output_image

  # enable filetype support (for readdir)
  p = Run(['tune2fs', '-O', 'filetype', output_image])
  p.communicate()
  assert p.returncode == 0, "failed to enable filetype support for " + output_image

  # set mount count to 1
  p = Run(['tune2fs', '-C', '1', output_image])
  p.communicate()
  assert p.returncode == 0, "failed to set mount count for " + output_image

  # check for errors
  p = Run(['e2fsck', '-fy', output_image])
  p.communicate()
  assert p.returncode < 4, "failed error check for " + output_image
