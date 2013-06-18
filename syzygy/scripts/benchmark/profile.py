#!python
# Copyright 2012 Google Inc. All Rights Reserved.
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

import glob
import logging
import optparse
import os
import os.path
import runner
import sys
import time


_LOGGER = logging.getLogger(__name__)


class ChromeProfileRunner(runner.ChromeRunner):
  def __init__(self, chrome_dir, output_dir, *args, **kw):
    chrome_exe = os.path.join(chrome_dir, 'chrome.exe')
    profile_dir = os.path.join(output_dir, 'profile')
    super(ChromeProfileRunner, self).__init__(chrome_exe,
                                              profile_dir,
                                              *args,
                                              **kw)
    self._output_dir = output_dir
    self._log_files = []

  def _PreIteration(self, it):
    super(ChromeProfileRunner, self)._PreIteration(it)
    self.StartLoggingRpc(self._output_dir)

  def _PostIteration(self, it, success):
    self.StopLoggingRpc()
    super(ChromeProfileRunner, self)._PostIteration(it, success)

  def _ProcessResults(self):
    # Capture all the binary trace log files that were generated.
    self._log_files = glob.glob(os.path.join(self._output_dir, '*.bin'))


class ChromeFrameProfileRunner(runner.ChromeFrameRunner):
  def __init__(self, chrome_dir, output_dir, *args, **kw):
    chrome_frame_dll = os.path.join(chrome_dir, 'npchrome_frame.dll')
    super(ChromeFrameProfileRunner, self).__init__(chrome_frame_dll,
                                                   *args,
                                                   **kw)
    self._output_dir = output_dir
    self._log_files = []

  def _PreIteration(self, it):
    super(ChromeFrameProfileRunner, self)._PreIteration(it)
    self.StartLoggingRpc(self._output_dir)

  def _PostIteration(self, it, success):
    self.StopLoggingRpc()
    super(ChromeFrameProfileRunner, self)._PostIteration(it, success)

  def _ProcessResults(self):
    # Capture all the binary trace log files that were generated.
    self._log_files = glob.glob(os.path.join(self._output_dir, '*.bin'))


# Give us silent access to the internals of our runner.
# pylint: disable=W0212
def ProfileChrome(chrome_dir, output_dir, iterations, chrome_frame,
                  startup_type=runner.DEFAULT_STARTUP_TYPE,
                  startup_urls=None):
  """Profiles the chrome instance in chrome_dir for a specified number
  of iterations. If chrome_frame is specified, also profiles Chrome Frame for
  the same number of iterations.

  Args:
    chrome_dir: the directory containing Chrome.
    output_dir: the directory where the call trace files are stored.
    iterations: the number of iterations to profile.
    chrome_frame: whether or not to profile Chrome Frame as well.
    session_urls: the list of URL to restore on Chrome startup.

  Raises:
    Exception on failure.
  """
  if not os.path.exists(output_dir):
    os.makedirs(output_dir)

  _LOGGER.info('Profiling Chrome "%s\chrome.exe".', chrome_dir)
  chrome_runner = ChromeProfileRunner(chrome_dir, output_dir,
                                      initialize_profile=True)
  chrome_runner.ConfigureStartup(startup_type, startup_urls)
  chrome_runner.Run(iterations)

  log_files = chrome_runner._log_files

  if chrome_frame:
    _LOGGER.info('Profiling Chrome Frame in "%s".', chrome_dir)
    chrome_frame_runner = ChromeFrameProfileRunner(chrome_dir, output_dir)
    chrome_frame_runner.Run(iterations)
    log_files.extend(chrome_frame_runner._log_files)

  return log_files


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
  parser.add_option('--chrome-frame', dest='chrome_frame',
                    default=False, action='store_true',
                    help='Also profile Chrome Frame in Internet Explorer.')
  parser.add_option('--input-dir', dest='input_dir',
                    help=('The input directory where the original Chrome '
                          'executables are to be found.'))
  parser.add_option('--output-dir', dest='output_dir',
                    help='The output directory for the call trace files.')
  parser.add_option('--startup-type', dest='startup_type', metavar='TYPE',
                    choices=runner.ALL_STARTUP_TYPES,
                    default=runner.DEFAULT_STARTUP_TYPE,
                    help='The type of Chrome session to open on startup. '
                         'Allowed values are: %s (default: %%default)' % (
                              ', '.join(runner.ALL_STARTUP_TYPES)))
  parser.add_option('--startup-url', dest='startup_urls', metavar='URL',
                    default=[], action='append',
                    help='Add URL to the startup scenario used for profiling. '
                         'This option may be given multiple times; each URL '
                         'will be added to the startup scenario.')
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
    ProfileChrome(opts.input_dir,
                  opts.output_dir,
                  opts.iterations,
                  opts.chrome_frame,
                  opts.startup_type,
                  opts.startup_urls)
  except Exception:
    _LOGGER.exception('Profiling failed.')
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
