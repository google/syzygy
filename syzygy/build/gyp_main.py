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

import os
import shlex
import sys
import vs_toolchain_wrapper

script_dir = os.path.dirname(os.path.realpath(__file__))
syzygy_src = os.path.abspath(os.path.join(script_dir, os.pardir, os.pardir))

sys.path.insert(0, os.path.join(syzygy_src, 'tools', 'gyp', 'pylib'))
import gyp


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
    applied_env_from_file = apply_gyp_environment_from_file(path)
    if (not applied_env_from_file or not os.environ.get('GYP_GENERATORS')):
      # Default to ninja if no generator has explicitly been set.
      os.environ['GYP_GENERATORS'] = 'ninja'
    if (not applied_env_from_file or not os.environ.get('GYP_MSVS_VERSION')):
      os.environ['GYP_MSVS_VERSION'] = '2015'


if __name__ == '__main__':
  # Get the path of the root 'src' directory.
  self_dir = os.path.abspath(os.path.dirname(__file__))
  src_dir = os.path.abspath(os.path.join(self_dir, '..', '..'))

  apply_syzygy_gyp_env(src_dir)
  assert os.environ.get('GYP_GENERATORS')

  if os.environ.get('GYP_GENERATORS') == 'msvs':
    print 'ERROR: The \'msvs\' configuration isn\'t supported anymore.'
    sys.exit(1)

  # Setup the VS toolchain.
  vs_runtime_dll_dirs =  \
      vs_toolchain_wrapper.SetEnvironmentAndGetRuntimeDllDirs()

  gyp_rc = gyp.main(sys.argv[1:])

  # Copy the VS runtime DLLs to the build directories.
  if vs_runtime_dll_dirs:
    x64_runtime, x86_runtime = vs_runtime_dll_dirs
    vs_toolchain_wrapper.CopyVsRuntimeDlls(
        os.path.join(src_dir, get_output_directory()),
        (x86_runtime, x64_runtime))

  sys.exit(gyp_rc)
