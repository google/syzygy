#!python
# Copyright 2015 Google Inc. All Rights Reserved.
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
"""A utility script to make sure that the minidump produced by SyzyASan gets
symbolized correctly.
"""

import logging
import minidump_symbolizer
import optparse
import os
import sys


_USAGE = """\
%prog [options]

Run the Asan symbolizer script on a minidump and ensure that the symbolization
is correct.
"""


def _ParseArguments():
  """Parse the command line arguments.

  Returns:
    The options on the command line.
  """
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--minidump', help='The minidump to process.')
  parser.add_option('--bug-type', help='The expected crash type.')
  parser.add_option('--access-mode', help='The expected access mode.')
  parser.add_option('--access-size', help='The expected access size.')
  parser.add_option('--corrupt-heap', action='store_true', default=False,
                    help='Indicates if we expect the heap to be corrupt')
  opts, _ = parser.parse_args()

  for path in minidump_symbolizer._DEFAULT_CDB_PATHS:
    if os.path.isfile(path):
      opts.cdb_path = path
      break
  if not opts.cdb_path:
    parser.error(
        'Unable to find cdb.exe. Make sure Windows SDK 8.0 is installed.')

  return opts


def main():
  logging.basicConfig(level=logging.DEBUG)
  logger = logging.getLogger()

  opts = _ParseArguments()

  report = minidump_symbolizer.ProcessMinidump(opts.minidump,
                                               opts.cdb_path,
                                               None)

  if report.bad_access_info['error_type'] != opts.bug_type:
    logger.error('Unexpected error type (expected %s, got %s).',
                 opts.bug_type, report.bad_access_info['error_type'])
    return 1

  if report.bad_access_info['access_mode'] != opts.access_mode:
    logger.error('Unexpected access mode (expected %s, got %s).',
                 opts.access_mode, report.bad_access_info['access_mode'])
    return 1

  if report.bad_access_info['access_size'] != opts.access_size:
    logger.error('Unexpected access size (expected %s, got %s).',
                 opts.access_size, report.bad_access_info['access_size'])
    return 1

  heap_is_corrupt = report.bad_access_info['heap_is_corrupt'] != '0'
  if opts.corrupt_heap != heap_is_corrupt:
    logger.error('Unexpected heap corruption state.')
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
