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
import glob
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
  def __init__(self, chrome_exe, output_dir, *args, **kw):
    profile_dir = os.path.join(output_dir, 'profile')
    super(ProfileRunner, self).__init__(chrome_exe, profile_dir, *args, **kw)
    self._output_dir = output_dir
    self._log_files = []

  def _SetUp(self):
    self.StartLoggingRpc(self._output_dir)

  def _TearDown(self):
    self.StopLoggingRpc()

  def _PreIteration(self, it):
    pass

  def _PostIteration(self, it, success):
    pass

  def _DoIteration(self, it):
    # Give Chrome some time to settle.
    time.sleep(10)

  def _ProcessResults(self):
    # Capture all the binary trace log files that were generated.
    self._log_files = glob.glob(os.path.join(self._output_dir, '*.bin'))


def ProfileChrome(chrome_dir, output_dir, iterations):
  """Profiles the chrome instance in chrome_dir for a specified number
  of iterations.

  Args:
    chrome_dir: the directory containing Chrome.
    output_dir: the directory where the call trace files are stored.
    iterations: the number of iterations to profile.

  Raises:
    Exception on failure.
  """
  chrome_exe = os.path.join(chrome_dir, 'chrome.exe')

  if not os.path.exists(output_dir):
    os.makedirs(output_dir)

  _LOGGER.info('Profiling Chrome "%s".', chrome_exe)
  runner = ProfileRunner(chrome_exe, output_dir)
  runner.Run(iterations)
  return runner._log_files


_USAGE = """\
%prog [options]

Profiles the instrumented Chrome executables supplied in an input directory,
by running them through the specified number of profile run iterations.
Stores the captured call trace files in the supplied output directory.
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
  parser.add_option('--output-dir', dest='output_dir',
                    help='The output directory for the call trace files.')
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
  opts.output_dir = os.path.abspath(opts.output_dir)

  return opts


def main():
  """Parses arguments and runs the optimization."""

  opts = _ParseArguments()

  try:
    trace_files = ProfileChrome(opts.input_dir,
                                opts.output_dir,
                                opts.iterations)
  except Exception:
    _LOGGER.exception('Profiling failed.')
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
