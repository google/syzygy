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
import os
import os.path
import pkg_resources
import re
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


class OptimizationError(Exception):
  """Raised on any failures in the optimization process."""
  pass


def _Subprocess(cmd_line):
  _LOGGER.info('Running command line %s', cmd_line)
  return subprocess.call(cmd_line)


def _RmTree(directory):
  '''Silently do a recursive delete on directory.'''
  # shutil.rmtree can't cope with read-only files.
  _Subprocess(['cmd', '/c', 'rmdir', '/s', '/q', directory])


_EXPECTED_DIRS = [ 'locales', 'servers', 'extensions' ]


def _PruneDirs(dirs):
  """Removes all unwanted directories from dirs, in place."""
  for unwanted in [d for d in dirs if d.lower() not in _EXPECTED_DIRS]:
    dirs.remove(unwanted)


_EXCLUDE_PATTERNS = [
    # Exclude all PDBs except for chrome_exe.pdb and chrome_dll.pdb.
    re.compile('^(?!(chrome_exe|chrome_dll)\.).+\.pdb$', re.I),
    # Exclude all test and chrome frame programs.
    re.compile('^.*(test|validate|example|sample).*$', re.I),
    # Exclude all zip/archive files.
    re.compile('^.+\.(7z|zip)$', re.I),
    ]


def _FilesToCopy(file_list):
  """Generates the filtered list of files to copy."""
  for file_name in file_list:
    if not any(p.match(file_name) for p in _EXCLUDE_PATTERNS):
      yield file_name


def _CopyChromeFiles(src_dir, tgt_dir, input_dll, input_pdb):
  """Copy all required chrome files from src_dir to tgt_dir."""
  src_dir = os.path.abspath(src_dir)
  tgt_dir = os.path.abspath(tgt_dir)
  if os.path.isdir(tgt_dir):
    _RmTree(tgt_dir)
  os.makedirs(tgt_dir)
  for root_dir, sub_dirs, file_list in os.walk(src_dir):
    _PruneDirs(sub_dirs)
    for dir_name in sub_dirs:
      sub_dir = os.path.join(tgt_dir, dir_name)
      _LOGGER.info('Creating "%s".', os.path.relpath(sub_dir, tgt_dir))
      os.mkdir(sub_dir)
    for file_name in _FilesToCopy(file_list):
      src = os.path.join(root_dir, file_name)
      rel_path = os.path.relpath(src, src_dir)
      tgt = os.path.join(tgt_dir, rel_path)
      _LOGGER.info('Copying "%s".', rel_path)
      try:
        shutil.copy2(src, tgt)
      except IOError:
        # When run as part of the build, there may be build targets still in
        # flight that we don't depend on and can't copy (because they're opened
        # exclusively by the build process).  Let's assume that all the files we
        # want will copy correctly, ignore the exeption, and hope for the best
        # on the other side.
        _LOGGER.warn('Skipped "%s".', rel_path)
        pass

  if input_dll:
    chrome_dll = os.path.join(tgt_dir, 'chrome.dll')
    _LOGGER.info('Copying "%s" to "%s"', input_dll, chrome_dll)
    shutil.copy2(input_dll, chrome_dll)

  if input_pdb:
    chrome_dll_pdb = os.path.join(tgt_dir, 'chrome_dll.pdb')
    _LOGGER.info('Copying "%s" to "%s"', input_pdb, chrome_dll_pdb)
    shutil.copy2(input_pdb, chrome_dll_pdb)


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


def _InstrumentChrome(chrome_dir, temp_dir, input_dll=None, input_pdb=None):
  _LOGGER.info('Copying chrome files from "%s" to "%s".', chrome_dir, temp_dir)
  _CopyChromeFiles(chrome_dir, temp_dir, input_dll, input_pdb)

  # Drop call_trace.dll in the temp dir.
  shutil.copy2(runner._GetExePath('call_trace.dll'), temp_dir)

  for file in _EXECUTABLES:
    _LOGGER.info('Instrumenting "%s".', file)
    src_file = os.path.join(temp_dir, file)
    dst_file = os.path.join(temp_dir, file)
    cmd = [runner._GetExePath('instrument.exe'),
           '--input-dll=%s' % src_file,
           '--output-dll=%s' % dst_file]

    ret = _Subprocess(cmd)
    if ret != 0:
      raise OptimizationError('Failed to instrument "%s".' % file)


def _ProfileChrome(temp_dir, iterations):
  _LOGGER.info('Profiling Chrome.')
  chrome_exe = os.path.join(temp_dir, 'instrumented', 'chrome.exe')
  runner = ProfileRunner(chrome_exe, temp_dir)
  runner.Run(iterations)
  return runner._log_files


def _OptimizeChrome(chrome_dir, temp_dir, output_dir, log_files,
                    input_dll=None, input_pdb=None):
  _LOGGER.info('Optimizing Chrome.')
  # Generate the ordering file for chrome.dll.

  cmd = [runner._GetExePath('reorder.exe'),
         '--verbose',
         '--output-stats',
         '--input-dll=%s' % (input_dll if input_dll
                             else os.path.join(chrome_dir, 'chrome.dll')),
         '--instrumented-dll=%s' % os.path.join(temp_dir,
                                                r'instrumented', 'chrome.dll'),
         '--output-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  cmd.extend(log_files)
  ret = _Subprocess(cmd)
  if ret != 0:
    raise OptimizationError('Failed to generate an ordering for chrome.dll')

  if os.path.isdir(output_dir):
    _LOGGER.info('Removing pre-existing output dir "%s".', output_dir)
    _RmTree(output_dir)

  _LOGGER.info('Copying "%s" to output dir "%s".', chrome_dir, output_dir)
  _CopyChromeFiles(chrome_dir, output_dir, input_dll, input_pdb)
  cmd = [runner._GetExePath('relink.exe'),
         '--verbose',
         '--input-dll=%s' % os.path.join(output_dir, 'chrome.dll'),
         '--input-pdb=%s' % os.path.join(output_dir, 'chrome_dll.pdb'),
         '--output-dll=%s' % os.path.join(output_dir, 'chrome.dll'),
         '--output-pdb=%s' % os.path.join(output_dir, 'chrome_dll.pdb'),
         '--order-file=%s' % os.path.join(temp_dir, 'chrome.dll-order.json'),]
  ret = _Subprocess(cmd)
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
  parser.add_option('--input-dll', dest='input_dll',
                    help=('Override the location of the input dll to'
                          'optimize.'))
  parser.add_option('--input-pdb', dest='input_pdb',
                    help=('Override the location of the input dll to'
                          'optimize.'))
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
  try:
    _InstrumentChrome(opts.input_dir, instrumented_dir,
                      input_dll=opts.input_dll, input_pdb=opts.input_pdb)
    _ProfileChrome(temp_dir, opts.iterations)
    trace_files = [os.path.join(temp_dir, 'kernel.etl'),
                   os.path.join(temp_dir, 'call_trace.etl'),]
    _OptimizeChrome(opts.input_dir, temp_dir, opts.output_dir, trace_files,
                    input_dll=opts.input_dll, input_pdb=opts.input_pdb)
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
      _RmTree(temp_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main())
