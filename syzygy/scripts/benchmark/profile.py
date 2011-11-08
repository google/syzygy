#!python
# Copyright 2011 Google Inc.
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
"""A utility script to automate the process of instrumenting, profiling and
optimizing Chrome."""

import chrome_utils
import instrument
import logging
import optparse
import os
import os.path
import runner
import shutil
import sys
import tempfile
import time


_LOGGER = logging.getLogger(__name__)


class ProfileRunner(runner.ChromeRunner):
  def __init__(self, chrome_exe, temp_dir, *args, **kw):
    profile_dir = os.path.join(temp_dir, 'profile')
    super(ProfileRunner, self).__init__(chrome_exe, profile_dir, *args, **kw)
    self._temp_dir = temp_dir
    self._log_files = []

  def _SetUp(self):
    self.StartLogging(self._temp_dir)

    call_trace_file = os.path.join(self._temp_dir, 'call_trace.etl')
    kernel_file = os.path.join(self._temp_dir, 'kernel.etl')
    self._log_files.append(call_trace_file)
    self._log_files.append(kernel_file)

  def _TearDown(self):
    self.StopLogging()

  def _PreIteration(self, it):
    pass

  def _PostIteration(self, it, success):
    pass

  def _DoIteration(self, it):
    # Give Chrome some time to settle.
    time.sleep(20)

  def _ProcessResults(self):
    # TODO(siggi): Generate ordering here?
    pass


def ProfileChrome(chrome_dir, iterations):
  """Profiles the chrome instance in chrome_dir for a specified number
  of iterations.

  Args:
    chrome_dir: the directory containing chrome.
    iterations: the number of iterations to profile.

  Raises:
    Exception on failure.
  """
  chrome_exe = os.path.join(chrome_dir, 'chrome.exe')

  _LOGGER.info('Profiling Chrome "%s".', chrome_exe)
  runner = ProfileRunner(chrome_exe, chrome_dir)
  runner.Run(iterations)
  return runner._log_files


_USAGE = """\
%prog [options]

Profiles the Chrome executables supplied in an input directory by running them
through the specified number of profile run iterations.
"""


def _ParseArguments():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--verbose', dest='verbose',
                    default=False, action='store_true',
                    help='Verbose logging.')
  parser.add_option('--iterations', dest='iterations', type='int',
                    default=10,
                    help='Number of profile iterations, 10 by default.')
  parser.add_option('--input-dir', dest='input_dir',
                    help=('The input directory where the original Chrome '
                          'executables are to be found.'))
  parser.add_option('--keep-temp-dirs', dest='keep_temp_dirs',
                    action='store_true',
                    help='Keep temporary directories instead of deleting them.')
  (opts, args) = parser.parse_args()

  if len(args):
    parser.error('Unexpected argument(s).')

  # Minimally configure logging.
  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.WARNING)

  if not opts.input_dir or not opts.output_dir:
    parser.error('You must provide input and output directories')

  opts.input_dir = os.path.abspath(opts.input_dir)

  return opts


def main():
  """Parses arguments and runs the optimization."""

  opts = _ParseArguments()

  try:
    trace_files = ProfileChrome(opts.input_dir, opts.iterations)
  except Exception:
    _LOGGER.exception('Profiling failed.')
    return 1
  finally:
    if opts.keep_temp_dirs:
      _LOGGER.info('Keeping temporary directory "%s".', temp_dir)
    else:
      _LOGGER.info('Deleting temporary directory "%s".', temp_dir)
      chrome_utils.RmTree(temp_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())
