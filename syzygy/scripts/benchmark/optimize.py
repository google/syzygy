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


_LOGGER = logging.getLogger(__name__)


class OptimizationError(Exception):
  """Raised on any failures in the optimization process."""
  pass


def _ProcessBBEntries(log_files, output_dir):
  """Summarize the basic-block entry counts in @p log_files to a JSON file in
  @p output_dir.

  The file path to the generated JSON file is returned.
  """
  output_file = os.path.join(output_dir, 'bbentries.json')
  cmd = [
      runner._GetExePath('grinder.exe'),
      '--mode=bbentry',
      '--output-file=%s' % output_file,
  ]
  cmd.extend(log_files)
  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to process basic-block entries.')
  return output_file


def _InstrumentAndProfile(work_dir, mode, opts):
  """Generate an instrumented chrome directory for @p mode in @p workdir using
  the given @p opts and profile it.

  If the mode is 'bbentry' generate a summary JSON file.

  Returns the list of trace or summary files.
  """
  instrumented_dir = os.path.join(work_dir, mode, 'instrumented')
  profile_data_dir = os.path.join(work_dir, mode, 'profile-data')

  # Instrument the provided Chrome executables in input_dir, and store
  # the profiled executables in instrumented_dir.
  instrument.InstrumentChrome(opts.input_dir, instrumented_dir, mode)

  # Then profile the instrumented executables in instrumented_dir.
  trace_files = profile.ProfileChrome(instrumented_dir,
                                      profile_data_dir,
                                      opts.iterations,
                                      opts.chrome_frame,
                                      opts.startup_type,
                                      opts.startup_urls)

  # For bbentry mode we need to run the grinder to generate a summary file
  # to return.
  if mode == 'bbentry':
    summary_file = _ProcessBBEntries(trace_files, work_dir)
    return [summary_file]

   # Otherwise we just return the raw set of trace files.
  return trace_files


# Give us silent access to the internals of our runner.
# pylint: disable=W0212
def _OptimizeChrome(chrome_dir, work_dir, output_dir, log_files, bb_entry_file):
  """Generate an optimized version of the chome.dll in @p chrome_dir based on
  the calltrace instrumented version of chrome.dll in @p work_dir, the
  calltrace @p log_files and an optional JSON @p bb_entry_file.

  The optimized chrome will be written to @p output_dir.
  """
  # Calculate all the path parameters.
  input_image = os.path.join(chrome_dir, 'chrome.dll')
  instrumented_image = os.path.join(
      work_dir, 'calltrace', 'instrumented', 'chrome.dll')
  order_file = os.path.join(work_dir, 'chrome.dll-order.json')
  output_image = os.path.join(output_dir, 'chrome.dll')
  output_pdb = os.path.join(output_dir, 'chrome.dll.pdb')

  # Generate the ordering file for chrome.dll.
  _LOGGER.info('Generating ordering file for Chrome.')
  cmd = [
      runner._GetExePath('reorder.exe'),
      '--verbose',
      '--output-stats',
      '--input-image=%s' % input_image,
      '--instrumented-image=%s' % instrumented_image,
      '--output-file=%s' % order_file,
  ]
  if bb_entry_file:
    cmd.append('--basic_block_entry_counts=%s' % bb_entry_file)
  cmd.extend(log_files)
  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to generate an ordering for chrome.dll')

  # Populate output_dir with a copy of the original chome installation.
  _LOGGER.info('Copying "%s" to output dir "%s".', chrome_dir, output_dir)
  if os.path.isfile(output_dir):
    raise OptimizationError('File present at output dir location: "%s"',
                            output_dir)
  chrome_utils.CopyChromeFiles(chrome_dir, output_dir)

  # Replace chrome.dll in output_dir with an optimized version.
  _LOGGER.info('Optimizing chrome.dll')
  cmd = [runner._GetExePath('relink.exe'),
         '--verbose',
         '--input-image=%s' % input_image,
         '--output-image=%s' % output_image,
         '--output-pdb=%s' % output_pdb,
         '--order-file=%s' % order_file,
         '--overwrite']
  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to relink chrome.dll')


def _CopyBinaries(src_dir, tgt_dir):
  """Copies the chrome dll and pdb files from @p src_dir to @p tgt_dir."""
  if not os.path.isdir(tgt_dir):
    _LOGGER.info('_CopyBinaries target dir not found. Creating "%s"', tgt_dir)
    os.makedirs(tgt_dir)

  files = ('chrome.dll', 'chrome.dll.pdb')
  for path in files:
    src_file = os.path.join(src_dir, path)
    tgt_file = os.path.join(tgt_dir, path)
    _LOGGER.info('Placing optimized %s in %s', path, tgt_dir)
    shutil.copy2(src_file, tgt_file)


_USAGE = """%prog [options]

Instruments, then profiles the Chrome executables supplied in an input directory
for a number of iterations, then optimizes the executable order with respect to
the profile runs.
"""


def _ParseArguments():
  """Parse the sys.argv command-line arguments, returning the options."""
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--verbose', dest='verbose',
                    default=False, action='store_true',
                    help='Verbose logging.')
  parser.add_option('--iterations', dest='iterations', type='int',
                    default=10,
                    help='Number of profile iterations, 10 by default.')
  parser.add_option('--chrome-frame', dest='chrome_frame',
                    default=False, action='store_true',
                    help=('Optimize for both Chrome Frame and Chrome usage '
                          'patterns. Without this flag, optimize only for '
                          'Chrome usage patterns.'))
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
                    help='Keep temp directories instead of deleting them.')
  parser.add_option('--mode',
                    choices=instrument.MODES,
                    default=instrument.DEFAULT_MODE,
                    help='The instrumentation mode. Allowed values are: '
                         '%s (default: %%default).' % (
                              ', '.join(instrument.MODES)))
  parser.add_option('--startup-type', dest='startup_type', metavar='TYPE',
                    choices=runner.ALL_STARTUP_TYPES,
                    default=runner.DEFAULT_STARTUP_TYPE,
                    help='The type of Chrome session to open on startup. The '
                         'allowed values are: %s (default: %%default).' %  (
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
  if opts.copy_to:
    opts.copy_to = os.path.abspath(opts.copy_to)

  return opts


def main():
  """Parses arguments and runs the optimization."""
  opts = _ParseArguments()

  work_dir = tempfile.mkdtemp(prefix='chrome-instr')
  _LOGGER.info('Created working directory "%s".', work_dir)

  try:
    # We always instrument in calltrace mode to be able to generate a coarse
    # function layout for the binary.
    trace_files = _InstrumentAndProfile(work_dir, 'calltrace', opts)

    # If we're in bbentry mode then we further instrument and profile to get
    # summary stats for basic-block entry counts.
    if opts.mode == 'bbentry':
      bb_entry_file = _InstrumentAndProfile(work_dir, 'bbentry', opts)[0]
    else:
      bb_entry_file = None

    # Lastly generate an ordering, and reorder the inputs to
    # the output dir.
    _OptimizeChrome(
        opts.input_dir, work_dir, opts.output_dir, trace_files, bb_entry_file)
    if opts.copy_to:
      _CopyBinaries(opts.output_dir, opts.copy_to)
  except OptimizationError:
    _LOGGER.exception('Optimization failed.')
    return 1
  finally:
    if opts.keep_temp_dirs:
      _LOGGER.info('Keeping temporary directory "%s".', work_dir)
    else:
      _LOGGER.info('Deleting temporary directory "%s".', work_dir)
      chrome_utils.RmTree(work_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())
