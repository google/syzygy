# Copyright 2012 Google Inc. All Rights Reserved.
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
"""A utility script to create a pristine new python virtual enviroment during
building."""
import datetime
import logging
import optparse
import os
import shutil
import subprocess
import sys


_SRC_DIR = os.path.abspath(os.path.join(__file__, '../../..'))
_VIRTUALENV_DIR = os.path.join(_SRC_DIR, 'third_party/virtualenv/files')


_LOGGER = logging.getLogger(__name__)


class VirtualEnvCreationError(RuntimeError):
  """Exception thrown on virtual enviroment creation error."""
  pass


def _Subprocess(command, failure_msg):
  _LOGGER.info('Executing command line %s.', command)
  ret = subprocess.call(command)
  if ret != 0:
    _LOGGER.error(failure_msg)
    raise VirtualEnvCreationError(failure_msg)


def _CreateVirtualEnv(base_dir):
  """Creates a new virtual python environment in base_dir, sets convenient
  defaults for it, and installs the external modules we need.
  Currently those modules are:
    - numpy.
    - matplotlib.

  Raises a VirtualEnvCreationError on failure.
  """
  # We want all paths to be absolute.
  base_dir = os.path.abspath(base_dir)

  if os.path.exists(base_dir):
    command = ['cmd', '/c', 'rmdir', '/s', '/q', base_dir]
    _Subprocess(command, 'Failed to delete existing directory')

  # Start by creating the output directory and copying python26.dll, as well
  # as pywintypes26.dll into it, as if the DLLs are not in path, the virtual
  # environment won't work.
  script_dir = os.path.join(base_dir, 'Scripts')
  try:
    os.makedirs(script_dir)
    dll_path = os.path.join(os.path.dirname(sys.executable), 'python26.dll')
    shutil.copy(dll_path, script_dir)

    dll_path = os.path.join(os.path.dirname(sys.executable), 'pywintypes26.dll')
    shutil.copy(dll_path, script_dir)

    dll_path = os.path.join(os.path.dirname(sys.executable), 'pythoncom26.dll')
    shutil.copy(dll_path, script_dir)
  except Exception:
    _LOGGER.exception('Unable to copy python DLL')
    raise VirtualEnvCreationError('Unable to copy python DLL')

  # Run virtualenv.py with our selfsame python interpreter.
  command = [sys.executable,
             os.path.join(_VIRTUALENV_DIR, 'virtualenv.py'),
             '--verbose',
             '--never-download',
             base_dir]
  _Subprocess(command, 'Virtualenv creation failed.')

  # Set defaults for setuptools so that our built eggs get deposited
  # to the release directory, and so that installing looks there.
  opts = (
      # Tag eggs with the SVN revision by default.
      ('egg_info', 'tag-svn-revision', 'True'),
      # Drop created eggs in the base directory's parent dir (Debug or Release).
      ('bdist_egg', 'dist-dir', os.path.join(base_dir, '..')),
      # Tell easy install to use the parent dir as the package index by default.
      ('easy_install', 'index-url', os.path.join(base_dir, '..')),
    )

  for (cmd, option, value) in opts:
    command = [os.path.join(script_dir, 'python'),
               '-c', 'from setuptools import setup; setup()',
               'setopt',
               '--global-config',
               '--command', cmd,
               '--option', option,
               '--set-value', value]
    _Subprocess(command, 'Failed to set option %s' % option)

  # Hook numpy into the virtual environment by copying it in.
  try:
    numpy_dir = os.path.join(_SRC_DIR, 'third_party/numpy/files/numpy')
    site_lib_dir = os.path.join(base_dir, 'Lib/site-packages')
    shutil.copytree(numpy_dir, os.path.join(site_lib_dir, 'numpy'))
  except Exception:
    _LOGGER.exception('Unable to copy numpy.')
    raise VirtualEnvCreationError('Unable to copy numpy.')

  # Install matplotlib into the new environment. We use easy_install to do
  # the needful, but provide it with an index URL that's the directory
  # containing the matplotlib subdir.
  matplotlib_dir = os.path.abspath(os.path.join(_SRC_DIR, 'third_party'))
  command = [os.path.join(script_dir, 'easy_install'),
             '--index-url', matplotlib_dir,
             'matplotlib']
  _Subprocess(command, 'Matplotlib installation failed.')


def _ParseArgs():
  parser = optparse.OptionParser(usage='%prog [options]')
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('', '--output-dir', dest='output_dir',
                    help='The base directory for the new virtual environment')
  parser.add_option('', '--success-file', dest='success_file',
                    default=None,
                    help='Path to a file that will be touched on successful '
                         'virtual environment creation')

  (opts, args) = parser.parse_args()
  if args:
    parser.error('This script takes no arguments.')
  if not opts.output_dir:
    parser.error('You must provide an output directory.')

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return (opts, args)


def Main():
  """Main function."""
  opts, dummy_args = _ParseArgs()
  _CreateVirtualEnv(opts.output_dir)

  if opts.success_file:
    with open(opts.success_file, 'w') as success_file:
      success_file.write(str(datetime.datetime.now()))

  return 0


if __name__ == '__main__':
  sys.exit(Main())
