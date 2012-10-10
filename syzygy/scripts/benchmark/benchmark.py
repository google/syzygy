#!/usr/bin/python2.6
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
import collections
import ibmperf
import logging
import optparse
import os.path
import runner
import sys
import textwrap


_USAGE = """\
%prog [options] chrome-executable

Benchmarks the Chrome executable provided for a number of iterations,
tallies the results and prints them out to STDOUT in a format suitable
for the Chrome dashboard scripts.
"""


def _GetOptionParser():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--verbose', dest='verbosity',
                    default=0, action='count',
                    help='Verbose logging. Call repeatedly for increased '
                         'verbosity.')
  parser.add_option('--user-data-dir', dest='profile',
                    help='The profile directory to use for the benchmark. '
                         'If not specified, uses a temporary directory.')
  parser.add_option('--iterations', dest='iterations', type='int',
                    default=10,
                    help="Number of iterations, 10 by default.")
  parser.add_option('--preload', dest='preload', type='int',
                    default=100,
                    help='The percentage of chrome.dll to preload.')
  parser.add_option('--no-preload', dest='preload', action='store_const',
                    const=0,
                    help='Do not preload chrome.dll. This is equivalent to '
                         '--preload=0. Retained for legacy compability.')
  parser.add_option('--cold-start', dest='cold_start', action='store_true',
                    default=False,
                    help='Test cold start by creating a shadow volume of the '
                         'volume Chrome resides on and running it from that '
                         'newly mounted volume for each iteration of the '
                         'test.')
  parser.add_option('--no-prefetch', dest='prefetch', action='store_const',
                    const=runner.Prefetch.DISABLED,
                    default=runner.Prefetch.ENABLED,
                    help='Turn OS pre-fetch off (on by default).')
  parser.add_option('--no-prefetch-first-launch',
                    dest='prefetch', action='store_const',
                    const=runner.Prefetch.RESET_PRIOR_TO_FIRST_LAUNCH,
                    help='Remove OS pre-fetch files prior to the first launch '
                         'of Chrome, but not prior to each iteration.')
  parser.add_option('--keep-temp-dirs', dest='keep_temp_dirs',
                    action='store_true', default=False,
                    help='Keep the temporary directories created during '
                         'benchmarking. This makes it easy to look at the '
                         'resultant log files.')
  parser.add_option('--no-initialize-profile', dest='initialize_profile',
                    action='store_false', default=True,
                    help='Skip the first run of Chrome, which is normally '
                         'launched to ensure that the profile directory '
                         'exists and is up to date.')
  parser.add_option('--ibmperf-dir', dest='ibmperf_dir',
                    default=ibmperf.DEFAULT_DIR,
                    help='Sets the folder containing IBM Performance '
                         'Inspector binaries. Defaults to "%s".' %
                         ibmperf.DEFAULT_DIR)
  parser.add_option('--ibmperf-run', dest='ibmperf_run',
                    action='store_true', default=False,
                    help='Indicates that IBM performance metrics should be '
                         'gathered. Note that only one metric can be gathered '
                         'at a time, thus the true number of iterations will '
                         'be iterations * number of metrics.')
  parser.add_option('--ibmperf-metric', dest='ibmperf_metrics',
                    action='append', default=[],
                    help='Sets a metric to be gathered using IBM Performance '
                         'Inspector. Multiple metrics may be set. If no '
                         'metrics are defined, and ibmperf-run is true, then '
                         'all metrics will be run.')
  parser.add_option('--ibmperf-list-metrics', dest='ibmperf_list_metrics',
                    action='store_true', default=False,
                    help='Lists the available metrics and exits.')
  parser.add_option('--trace-file-archive-dir', metavar='DIR',
                    help='Directory in which to archive the ETW trace logs')
  parser.add_option('--startup-type', dest='startup_type', metavar='TYPE',
                    choices=runner.ALL_STARTUP_TYPES,
                    default=runner.DEFAULT_STARTUP_TYPE,
                    help='The type of Chrome session to open on startup. '
                         'Must be one of: %s. (default: %%default)' % (
                             ', '.join(runner.ALL_STARTUP_TYPES)))
  parser.add_option('--startup-url', dest='startup_urls', metavar='URL',
                    default=[], action='append',
                    help='URL with which to seed the profile. This option is '
                         'repeatable, once per URL to include.')
  return parser


# Use for converting a verbosity level to a logging level. Anything 2 and
# above maps to DEBUG output.
_VERBOSITY_LEVELS = collections.defaultdict(lambda: logging.DEBUG,
    {0: logging.WARNING, 1: logging.INFO})


def ListIbmPerfMetrics():
  """Lists the available hardware performance counters and returns 0."""
  hpc = ibmperf.HardwarePerformanceCounter()
  print('At most %d performance counters may be gathered at one time.\n'
        'Free counters do not count towards this total.\n' % hpc.max_counters)
  for name in sorted(hpc.metrics.keys()):
    category = ' (free)' if name in hpc.free_metrics else ''
    print('%s%s' % (name, category))
    desc = hpc.metrics[name]
    desc = textwrap.wrap(desc)
    for line in desc:
      print('    %s' % line)
  return 0


def main():
  """Parses arguments and runs benchmarks."""
  parser = _GetOptionParser()
  (opts, args) = parser.parse_args()

  # Minimally configure logging.
  logging.basicConfig(level=_VERBOSITY_LEVELS[opts.verbosity])

  # Handle support for listing the available metrics.
  if opts.ibmperf_list_metrics:
    return ListIbmPerfMetrics()

  if len(args) != 1:
    parser.error("You must provide the Chrome.exe instance to benchmark.")

  chrome_exe = args[0]
  if not os.path.exists(chrome_exe):
    parser.error("\"%s\" does not exist" % chrome_exe)

  benchmark_runner = runner.BenchmarkRunner(chrome_exe,
                                            opts.profile,
                                            opts.preload,
                                            opts.cold_start,
                                            opts.prefetch,
                                            opts.keep_temp_dirs,
                                            opts.initialize_profile,
                                            opts.ibmperf_dir,
                                            opts.ibmperf_run,
                                            opts.ibmperf_metrics,
                                            opts.trace_file_archive_dir)
  benchmark_runner.ConfigureStartup(opts.startup_type, opts.startup_urls)
  benchmark_runner.Run(opts.iterations)

  return 0


if __name__ == '__main__':
  sys.exit(main())
