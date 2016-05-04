# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A wrapper for the gyp_main that ensures the appropriate include directories
are brought in.
"""

import glob
import os
import shlex
import shutil
import sys
import vs_toolchain_wrapper


def apply_gyp_environment_from_file(file_path):
  """Reads in a *.gyp_env file and applies the valid keys to os.environ."""
  if not os.path.exists(file_path):
    return False
  with open(file_path, 'rU') as f:
    file_contents = f.read()
  try:
    file_data = eval(file_contents, {'__builtins__': None}, None)
  except SyntaxError, e:
    e.filename = os.path.abspath(file_path)
    raise
  supported_vars = (
      'GYP_DEFINES',
      'GYP_GENERATOR_FLAGS',
      'GYP_GENERATORS',
      'GYP_MSVS_VERSION',
  )
  for var in supported_vars:
    file_val = file_data.get(var)
    if file_val:
      if var in os.environ:
        print 'INFO: Environment value for "%s" overrides value in %s.' % (
            var, os.path.abspath(file_path)
        )
      else:
        os.environ[var] = file_val
  return True


def get_output_directory():
  """Returns the output directory that GYP will use."""

  # Handle generator flags from the environment.
  genflags = shlex.split(os.environ.get('GYP_GENERATOR_FLAGS', ''))

  needle = 'output_dir='
  for item in genflags:
    if item.startswith(needle):
      return item[len(needle):]

  return 'out'


def apply_syzygy_gyp_env(syzygy_src_path):
  if 'SKIP_SYZYGY_GYP_ENV' not in os.environ:
    # Update the environment based on syzygy.gyp_env
    path = os.path.join(syzygy_src_path, 'syzygy.gyp_env')
    if (not apply_gyp_environment_from_file(path) or
        not os.environ.get('GYP_GENERATORS')):
      # Default to ninja if no generator has explicitly been set.
      os.environ['GYP_GENERATORS'] = 'ninja'


def compare_files_timestamp(first_file, second_file):
  # Check if two files have the same timestamp.
  #
  # Returns True if both files exist and have the same timestamp, False
  # otherwise.
  if not os.path.exists(first_file) or not os.path.exists(second_file):
    return False
  # The Windows file system supports nanosecond resolution for the file stamps,
  # however, utimes (and indirectly shutil.copy2) only supports microsecond
  # resolution. Because of this the timestamp of 2 files that have been copied
  # with shutil.copy2 might be slightly different. Rounding this to the closest
  # second fix this and gives us a pretty good resolution.
  if int(os.stat(first_file).st_mtime) != int(os.stat(second_file).st_mtime):
    return False
  return True


if __name__ == '__main__':
  # Get the path of the root 'src' directory.
  self_dir = os.path.abspath(os.path.dirname(__file__))
  src_dir = os.path.abspath(os.path.join(self_dir, '..', '..'))

  apply_syzygy_gyp_env(src_dir)
  assert os.environ.get('GYP_GENERATORS')

  if os.environ.get('GYP_GENERATORS') == 'msvs':
    print 'ERROR: The \'msvs\' configuration isn\'t supported anymore.'
    sys.exit(1)

  # Get the path to src/build. This contains a bunch of gyp
  # 'plugins' that get called by common.gypi and base.gyp.
  build_dir = os.path.join(src_dir, 'build')

  # Get the path to the downloaded version of gyp.
  gyp_dir = os.path.join(src_dir, 'tools', 'gyp')

  # Get the path to the gyp module directoy, and the gyp_main
  # that we'll defer to.
  gyp_pylib = os.path.join(gyp_dir, 'pylib')
  gyp_main = os.path.join(gyp_dir, 'gyp_main.py')

  # Ensure the gyp plugin and module directories are in the module path
  # before passing execution to gyp_main.
  sys.path.append(gyp_pylib)
  sys.path.append(build_dir)

  # Setup the VS toolchain.
  vs_runtime_dll_dirs =  \
      vs_toolchain_wrapper.SetEnvironmentAndGetRuntimeDllDirs()
  if vs_runtime_dll_dirs:
    x64_runtime, x86_runtime = vs_runtime_dll_dirs
    vs_toolchain_wrapper.CopyVsRuntimeDlls(
        os.path.join(src_dir, get_output_directory()),
        (x86_runtime, x64_runtime))

  win_sdk_dir = os.environ.get('WINDOWSSDKDIR')
  if win_sdk_dir:
    dbg_dlls_dir = os.path.join(win_sdk_dir, 'Debuggers', 'x86')
    out_dir = os.path.join(src_dir, get_output_directory())
    for f in glob.glob(os.path.join(dbg_dlls_dir, '*.dll')):
      if not f.lower().startswith('dbg'):
        continue
      for c in ('Debug', 'Release'):
        out_name = os.path.join(out_dir, c, os.path.basename(f))
        if not compare_files_timestamp(f, out_name):
          print 'Copying %s to %s.' % (f, out_name)
          shutil.copy2(f, out_name)
  else:
    print ('Unable to locate the Windows SDK directory, please manually copy '
           '\{win_sdk_dir\}/Debuggers/x86/dbg*.dll to the build directory.')

  execfile(gyp_main)
