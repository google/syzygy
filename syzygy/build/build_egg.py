# Copyright 2011 Google Inc. All Rights Reserved.
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
"""A utility script to assist with building an .egg file for a package or
a script."""
import datetime
import optparse
import os
import logging
import shutil
import subprocess
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _Subprocess(command, failure_msg, **kw):
  _LOGGER.info('Executing command line %s.', command)
  ret = subprocess.call(command, **kw)
  if ret != 0:
    _LOGGER.error(failure_msg)
    raise RuntimeError(failure_msg)


def _BuildEgg(setup_file, build_dir, args):
  setup_file = os.path.abspath(setup_file)
  build_dir = os.path.abspath(build_dir)

  _LOGGER.info('Building "%s" in directory "%s".', setup_file, build_dir)

  # Start by ensuring the build directory is clean by
  # deleting it if it already existed.
  if os.path.isdir(build_dir):
    _LOGGER.info('Deleting build directory "%s".', build_dir)
    shutil.rmtree(build_dir)

  # Then (re-) create it.
  os.makedirs(build_dir)

  # We run the "egg_info", "build" and "bdist_egg" commands all in one go,
  # because they propagate information from one to the next.
  # TODO(siggi): This still litters the source directory with an "egg-info"
  #     folder. Ideally it should be possible to add an --egg-base parameter
  #     to the egg_info command, but for whatever reasons that results in an
  #     egg with no metadata.
  command = [sys.executable, setup_file, '--verbose']
  if args:
    command.extend(args)

  command.extend(['egg_info',
                  'build',
                      '--build-base', build_dir,
                  'bdist_egg',
                      '--keep-temp'])
  _Subprocess(command, 'Build failed', cwd=os.path.dirname(setup_file))


_USAGE = '%prog [options] -- [setup commands and arguments]'

def _ParseArgs():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('', '--setup-file', dest='setup_file',
                    help='The setup.py to build from.')
  parser.add_option('', '--build-dir', dest='build_dir',
                    help='The temporary build directory to use.')
  parser.add_option('', '--success-file', dest='success_file',
                    default=None,
                    help='Path to a file that will be touched on a successful '
                         'build')

  (opts, args) = parser.parse_args()
  if not opts.setup_file:
    parser.error('You must provide a setup file.')
  if not opts.build_dir:
    parser.error('You must provide a build directory.')

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  # Strip the arguments of trailing quote to get around a gyp bug:
  #     http://code.google.com/p/gyp/issues/detail?id=272
  args = [arg.rstrip('"\'') for arg in args]

  return (opts, args)


def main():
  """Main function."""
  opts, args = _ParseArgs()
  _BuildEgg(opts.setup_file, opts.build_dir, args)

  if opts.success_file:
    with open(opts.success_file, 'w') as success_file:
      success_file.write(str(datetime.datetime.now()))

  return 0


if __name__ == '__main__':
  sys.exit(main())
