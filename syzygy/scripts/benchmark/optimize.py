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

from etw.guiddef import GUID
import etw.evntrace
import logging
import optparse
import os.path
import pkg_resources
import runner
import shutil
import subprocess
import sys
import tempfile
import time


_EXECUTABLES = ['chrome.dll']


# From call_trace_defs.h.
_CALL_TRACE_PROVIDER = GUID('{06255E36-14B0-4E57-8964-2E3D675A0E77}')
_CALL_TRACE_LEVEL = etw.evntrace.TRACE_LEVEL_INFORMATION
_TRACE_FLAG_ENTER = 0x0001
_TRACE_FLAG_EXIT = 0x0002
_TRACE_FLAG_STACK_TRACES = 0x0002
_TRACE_FLAG_LOAD_EVENTS = 0x0008
_TRACE_FLAG_THREAD_EVENTS = 0x0010
_TRACE_FLAG_BATCH_ENTER = 0x0020


_LOGGER = logging.getLogger(__name__)


def _Subprocess(cmd_line):
  _LOGGER.info('Running command line %s', cmd_line)
  return subprocess.call(cmd_line)


def _RmTree(directory):
  '''Silently do a recursive delete on directory.'''
  # shutil.rmtree can't cope with read-only files.
  _Subprocess(['cmd.exe', '/c', 'rmdir.exe', '/s', '/q', directory])


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

  def _PostIteration(self, it):
    pass

  def _DoIteration(self, it):
    # Give Chrome some time to settle.
    time.sleep(20)

  def _ProcessResults(self):
    # TODO(siggi): Generate ordering here?
    pass

def _InstrumentChrome(chrome_dir, temp_dir):
  _LOGGER.info('Copying "%s" to "%s".', chrome_dir, temp_dir)
  shutil.copytree(chrome_dir, temp_dir)

  # Drop call_trace.dll in the temp dir.
  shutil.copy(runner._GetExePath('call_trace.dll'), temp_dir)

  for file in _EXECUTABLES:
    _LOGGER.info('Instrumenting "%s".', file)
    src_file = os.path.join(chrome_dir, file)
    dst_file = os.path.join(temp_dir, file)
    cmd = [runner._GetExePath('instrument.exe'),
           '--input-dll=%s' % src_file,
           '--output-dll=%s' % dst_file]

    ret = _Subprocess(cmd)
    if ret != 0:
      raise RuntimeError('Failed to instrument "%s".' % file)


def _ProfileChrome(temp_dir, iterations):
  _LOGGER.info('Profiling Chrome.')
  chrome_exe = os.path.join(temp_dir, 'instrumented/chrome.exe')
  runner = ProfileRunner(chrome_exe, temp_dir)
  runner.Run(iterations)
  return runner._log_files


def _OptimizeChrome(chrome_dir, temp_dir, output_dir, log_files):
  _LOGGER.info('Optimizing Chrome.')
  # Generate the ordering file for chrome.dll.
  cmd = [runner._GetExePath('reorder.exe'),
         '--verbose',
         '--output-stats',
         '--instrumented-dll=%s' % os.path.join(temp_dir,
                                                r'instrumented\chrome.dll'),
         '--output-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  cmd.extend(log_files)
  ret = _Subprocess(cmd)
  if ret != 0:
    raise RuntimeError('Failed to generate an ordering for chrome.dll')

  if os.path.isdir(output_dir):
    _LOGGER.info('Removing pre-existing output dir "%s".', output_dir)
    _RmTree(output_dir)

  _LOGGER.info('Copying "%s" to output dir "%s".', chrome_dir, output_dir)
  shutil.copytree(chrome_dir, output_dir)
  cmd = [runner._GetExePath('relink.exe'),
         '--verbose',
         '--input-dll=%s' % os.path.join(chrome_dir, 'chrome.dll'),
         '--input-pdb=%s' % os.path.join(chrome_dir, 'chrome_dll.pdb'),
         '--output-dll=%s' % os.path.join(output_dir, 'chrome.dll'),
         '--output-pdb=%s' % os.path.join(output_dir, 'chrome_dll.pdb'),
         '--order-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  ret = _Subprocess(cmd)
  if ret != 0:
    raise RuntimeError('Failed to reorder chrome.dll')


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
                    help='The input directory where the original Chrome '
                         'executables are to be found.')
  parser.add_option('--output-dir', dest='output_dir',
                    help='The output directory where the optimized executables '
                         'will be stored.')
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

  return opts


def main():
  """Parses arguments and runs the optimization."""

  opts = _ParseArguments()

  temp_dir = tempfile.mkdtemp(prefix='chrome-instr')
  _LOGGER.info('Created temporary directory "%s".', temp_dir)

  instrumented_dir = os.path.join(temp_dir, 'instrumented')
  try:
    _InstrumentChrome(opts.input_dir, instrumented_dir)
    _ProfileChrome(temp_dir, opts.iterations)
    trace_files = [os.path.join(temp_dir, 'kernel.etl'),
                   os.path.join(temp_dir, 'call_trace.etl'),]
    _OptimizeChrome(opts.input_dir, temp_dir, opts.output_dir, trace_files)
  finally:
    if opts.keep_temp_dirs:
      _LOGGER.info('Keeping temporary directory "%s".', temp_dir)
    else:
      _LOGGER.info('Deleting temporary directory "%s".', temp_dir)
      _RmTree(temp_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())
