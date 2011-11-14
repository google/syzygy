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
import profile
import runner
import shutil
import sys
import tempfile
import time


_LOGGER = logging.getLogger(__name__)


class OptimizationError(Exception):
  """Raised on any failures in the optimization process."""
  pass


def _OptimizeChrome(chrome_dir, temp_dir, output_dir, log_files):
  _LOGGER.info('Optimizing Chrome.')
  # Generate the ordering file for chrome.dll.

  cmd = [runner._GetExePath('reorder.exe'),
         '--verbose',
         '--output-stats',
         '--input-dll=%s' % os.path.join(chrome_dir, 'chrome.dll'),
         '--instrumented-dll=%s' % os.path.join(temp_dir,
                                                r'instrumented', 'chrome.dll'),
         '--output-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  cmd.extend(log_files)
  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to generate an ordering for chrome.dll')

  if os.path.isdir(output_dir):
    _LOGGER.info('Removing pre-existing output dir "%s".', output_dir)
    chrome_utils.RmTree(output_dir)

  _LOGGER.info('Copying "%s" to output dir "%s".', chrome_dir, output_dir)
  chrome_utils.CopyChromeFiles(chrome_dir, output_dir)
  cmd = [runner._GetExePath('relink.exe'),
         '--verbose',
         '--input-dll=%s' % os.path.join(chrome_dir, 'chrome.dll'),
         '--input-pdb=%s' % os.path.join(chrome_dir, 'chrome_dll.pdb'),
         '--output-dll=%s' % os.path.join(output_dir, 'chrome.dll'),
         '--output-pdb=%s' % os.path.join(output_dir, 'chrome_dll.pdb'),
         '--order-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to reorder chrome.dll')


def _CopyBinaries(src_dir, tgt_dir):
  files = ('chrome.dll', 'chrome_dll.pdb')
  for file in files:
    src_file = os.path.join(src_dir, file)
    tgt_file = os.path.join(tgt_dir, file)
    _LOGGER.info('Placing optimized %s in %s', file, tgt_dir)
    shutil.copy2(src_file, tgt_file)


_USAGE = """\
%prog [options]

Instruments, then profiles the Chrome executables supplied in an input directory
for a number of iterations, then optimizes the executable order with respect to
the profile runs.
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
                    help=('The directory where the optimized chrome '
                          'installation will be created. From this location, '
                          'one can subsequently run benchmarks.'))
  parser.add_option('--copy-to', dest='copy_to',
                    help=('(Optional) The output directory where the final '
                          'optimized PE and PDB files will be copied.'))
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
  opts.output_dir = os.path.abspath(opts.output_dir)
  if opts.copy_to:
    opts.copy_to = os.path.abspath(opts.copy_to)

  return opts


def main():
  """Parses arguments and runs the optimization."""

  opts = _ParseArguments()

  temp_dir = tempfile.mkdtemp(prefix='chrome-instr')
  _LOGGER.info('Created temporary directory "%s".', temp_dir)

  instrumented_dir = os.path.join(temp_dir, 'instrumented')
  profile_data_dir = os.path.join(temp_dir, 'profile_data')
  try:
    # Instrument the provided Chrome executables in input_dir, and store
    # the profiled executables in instrumented_dir.
    instrument.InstrumentChrome(opts.input_dir, instrumented_dir)

    # Then profile the instrumented executables in instrumented_dir.
    trace_files = profile.ProfileChrome(instrumented_dir,
                                        profile_data_dir,
                                        opts.iterations)
    # Lastly generate an ordering, and reorder the inputs to
    # the output dir.
    _OptimizeChrome(opts.input_dir, temp_dir, opts.output_dir, trace_files)
    if opts.copy_to:
      _CopyBinaries(opts.output_dir, opts.copy_to)
  except OptimizationError:
    _LOGGER.exception('Optimization failed.')
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
