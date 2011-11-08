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
"""A utility script to automate the process of instrumenting Chrome."""

import chrome_utils
import logging
import optparse
import os.path
import runner
import shutil
import sys


_EXECUTABLES = ['chrome.dll']


_LOGGER = logging.getLogger(__name__)


class InstrumentationError(Exception):
  """Raised on failure in the instrumentation process."""
  pass


def InstrumentChrome(chrome_dir, output_dir, input_dll=None, input_pdb=None):
  """Makes an instrumented copy of the Chrome files in chrome_dir in
  output_dir.

  Args:
    chrome_dir: the directory containing the input files.
    output_dir: the directory where the output will be generated.
    input_dll: the location of Chrome.dll. If not supplied the file in
        chrome_dir will be used.
    input_pdb: the location of Chrome_dll.pdb. If not supplied the file in
        chrome_dir will be used.

  Raises:
    InstrumentationError if instrumentation fails.
  """
  _LOGGER.info('Copying chrome files from "%s" to "%s".',
               chrome_dir,
               output_dir)
  chrome_utils.CopyChromeFiles(chrome_dir, output_dir, input_dll, input_pdb)

  # Drop call_trace.dll in the temp dir.
  shutil.copy2(runner._GetExePath('call_trace.dll'), output_dir)

  for file in _EXECUTABLES:
    _LOGGER.info('Instrumenting "%s".', file)
    src_file = os.path.join(output_dir, file)
    dst_file = os.path.join(output_dir, file)
    cmd = [runner._GetExePath('instrument.exe'),
           '--input-dll=%s' % src_file,
           '--output-dll=%s' % dst_file]

    ret = chrome_utils.Subprocess(cmd)
    if ret != 0:
      raise InstrumentationError('Failed to instrument "%s".' % file)


_USAGE = """\
%prog [options]

Copies the Chrome executables supplied in an input directory to an output
directory and instruments them at the destination. Leaves the instrumented
Chrome instance in the destination directory ready to use.
"""


def _ParseArguments():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--verbose', dest='verbose',
                    default=False, action='store_true',
                    help='Verbose logging.')
  parser.add_option('--input-dir', dest='input_dir',
                    help=('The input directory where the original Chrome '
                          'executables are to be found.'))
  parser.add_option('--output-dir', dest='output_dir',
                    help=('The directory where the optimized chrome '
                          'installation will be created. From this location, '
                          'one can subsequently run benchmarks.'))
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
  """Parses arguments and runs the instrumentation process."""

  opts = _ParseArguments()

  try:
    InstrumentChrome(opts.input_dir, opts.output_dir)
  except Exception:
    _LOGGER.exception('Instrumentation failed.')
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
