#!/usr/bin/python2.6
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
import logging
import optparse
import os.path
import runner
import sys


_USAGE = """\
%prog [options] chrome-executable

Benchmarks the Chrome executable provided for a number of iterations,
tallies the results and prints them out to STDOUT in a format suitable
for the Chrome dashboard scripts.
"""


def _GetOptionParser():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--verbose', dest='verbose',
                    default=False, action='store_true',
                    help='Verbose logging.')
  parser.add_option('--user-data-dir', dest='profile',
                    help='The profile directory to use for the benchmark.')
  parser.add_option('--iterations', dest='iterations', type='int',
                    default=10,
                    help="Number of iterations, 10 by default.")
  parser.add_option('--no-preload', dest='preload', action='store_false',
                    default=True,
                    help="Turn Chrome.dll pre-loading off (on by default).")
  parser.add_option('--cold-start', dest='cold_start', action='store_true',
                    default=False,
                    help='Test cold start by creating a shadow volume of the '
                          'volume Chrome resides on and running it from that '
                          'newly mounted volume for each iteration of the '
                          'test.')
  parser.add_option('--no-prefetch', dest='prefetch', action='store_false',
                    default=True,
                    help='Turn OS pre-fetch off (on by default).')
  parser.add_option('--keep-temp-dirs', dest='keep_temp_dirs',
                    action='store_true', default=False,
                    help='Keep the temporary directories created during '
                         'benchmarking. This makes it easy to look at the '
                         'resultant log files.')
  return parser


def main():
  """Parses arguments and runs benchmarks."""
  parser = _GetOptionParser()
  (opts, args) = parser.parse_args()
  if len(args) != 1:
    parser.error("You must provide the Chrome.exe instance to benchmark.")

  # Minimally configure logging.
  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.WARNING)

  chrome_exe = args[0]
  if not os.path.exists(chrome_exe):
    parser.error("\"%s\" does not exist" % chrome_exe)

  benchmark_runner = runner.BenchmarkRunner(chrome_exe,
                                            opts.profile,
                                            opts.preload,
                                            opts.cold_start,
                                            opts.prefetch,
                                            opts.keep_temp_dirs)
  try:
    benchmark_runner.Run(opts.iterations)
  except:
    logging.exception('Exception in Run.')

  return 0


if __name__ == '__main__':
  sys.exit(main())
