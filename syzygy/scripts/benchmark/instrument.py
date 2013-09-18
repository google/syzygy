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
"""A utility script to automate the process of instrumenting Chrome."""

import chrome_utils
import logging
import optparse
import os.path
import runner
import shutil
import sys


# These binaries will always be instrumented.
EXECUTABLES = ['chrome.dll']
# These binaries will only be instrumented if present.
EXECUTABLES_OPTIONAL = ['chrome_child.dll']


_LOGGER = logging.getLogger(__name__)


class InstrumentationError(Exception):
  """Raised on failure in the instrumentation process."""
  pass


_MODE_INFO = {
  'asan': 'syzyasan_rtl.dll',
  'bbentry': 'basic_block_entry_client.dll',
  'calltrace': 'call_trace_client.dll',
  'coverage': 'coverage_client.dll',
  'fuzzing': None,
  'profile' : 'profile_client.dll'
}
MODES = _MODE_INFO.keys()
DEFAULT_MODE = 'calltrace'


def InstrumentExecutable(
    chrome_dir, output_dir, mode, args, agent_dll, executable, optional):
  """Makes an instrumented copy of the Chrome files in |chrome_dir| in
  |output_dir|.

  Args:
    chrome_dir: the directory containing the input files.
    output_dir: the directory where the output will be generated.
    mode: the instrumentation mode to use.
    args: additional arguments for instrument.exe
    agent_dll: the basename of the agent DLL to use.
    executable: the basename of the executable to instrument.
    optional: if True then this will succeed even if the binary does not
        exist; otherwise, this will fail if the binary does not exist.

  Raises:
    InstrumentationError if instrumentation fails.
  """
  src_file = os.path.join(chrome_dir, executable)
  if not os.path.isfile(src_file):
    if not optional:
      raise InstrumentationError('Missing mandatory "%s".' % executable)
    _LOGGER.info('Not instrumenting missing optional "%s".', executable)
    return

  _LOGGER.info('Instrumenting %s "%s".',
               "optional" if optional else "mandatory",
               executable)
  dst_file = os.path.join(output_dir, executable)

  # In generating the command-line we place the additional arguments first
  # so that we can subsequently override those arguments we explicitly set.
  cmd = [runner._GetExePath('instrument.exe')]
  cmd += args
  cmd += ['--input-image=%s' % src_file,
          '--output-image=%s' % dst_file,
          '--mode=%s' % mode,
          '--overwrite']

  if agent_dll:
    cmd.append('--agent=%s' % agent_dll)

  if mode == 'profile':
    cmd.append('--no-interior-refs')

  ret = chrome_utils.Subprocess(cmd)
  if ret != 0:
    raise InstrumentationError('Failed to instrument "%s".' % executable)


# Give us silent access to internal member functions of the runner.
# pylint: disable=W0212
def InstrumentChrome(chrome_dir, output_dir, mode, args):
  """Makes an instrumented copy of the Chrome files in chrome_dir in
  output_dir.

  Args:
    chrome_dir: the directory containing the input files.
    output_dir: the directory where the output will be generated.
    mode: the instrumentation mode to use.
    args: additional arguments for instrument.exe

  Raises:
    InstrumentationError if instrumentation fails.
  """
  if mode not in _MODE_INFO:
    raise InstrumentationError("Unrecognized mode: %s" % mode)

  _LOGGER.info('Copying chrome files from "%s" to "%s".',
               chrome_dir,
               output_dir)
  chrome_utils.CopyChromeFiles(chrome_dir, output_dir)

  # Drop the agent DLL, if any, into the output dir.
  agent_dll = _MODE_INFO[mode]
  if agent_dll:
    shutil.copy2(runner._GetExePath(agent_dll), output_dir)

  for path in EXECUTABLES:
    InstrumentExecutable(
        chrome_dir, output_dir, mode, args, agent_dll, path, False)

  for path in EXECUTABLES_OPTIONAL:
    InstrumentExecutable(
        chrome_dir, output_dir, mode, args, agent_dll, path, True)


_USAGE = """\
%prog [options] [-- additional options for instrument.exe]

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
                    help=('The directory where the optimized Chrome '
                          'installation will be created. From this location, '
                          'one can subsequently run benchmarks.'))
  parser.add_option('--mode', choices=MODES, default=DEFAULT_MODE,
                    help='The instrumentation mode. Allowed values are '
                         ' %s (default: %%default).' % ', '.join(MODES))
  (opts, args) = parser.parse_args()

  # Minimally configure logging.
  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.WARNING)

  if not opts.input_dir or not opts.output_dir:
    parser.error('You must provide input and output directories.')

  opts.input_dir = os.path.abspath(opts.input_dir)
  opts.output_dir = os.path.abspath(opts.output_dir)

  return (opts, args)


def main():
  """Parses arguments and runs the instrumentation process."""

  opts, args = _ParseArguments()

  try:
    InstrumentChrome(opts.input_dir, opts.output_dir, opts.mode, args)
  except Exception:
    _LOGGER.exception('Instrumentation failed.')
    return 1

  return 0


if __name__ == '__main__':
  sys.exit(main())
