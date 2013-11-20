#!python
# Copyright 2012 Google Inc. All Rights Reserved.
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
"""A utility script to perform code coverage analysis."""
import glob
import logging
import optparse
import os
import shutil
import subprocess
import sys
import tempfile


# The list of DLLs we want to instrument in addition to _unittests executables.
_DLLS_TO_INSTRUMENT = [
    'basic_block_entry_client.dll',
    'call_trace_client.dll',
    'coverage_client.dll',
    'profile_client.dll',
    'syzyasan_rtl.dll',
]


# The list of file patterns to copy to the staging/coverage area.
_FILE_PATTERNS_TO_COPY = [
    '*_tests.exe',
    '*_unittests.exe',
    '*.dll',
    '*.pdb',
    'test_data',
    'call_trace_service.exe',
]

_SYZYGY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


# This is hardcoded to the Visual Studio default install location.
_PERF_TOOLS_DIR = ('C:/Program Files (x86)/Microsoft Visual Studio 9.0/'
                   'Team Tools/Performance Tools')


_COVERAGE_ANALYZER_DIR = os.path.normpath(
    os.path.join(_SYZYGY_DIR, '../third_party/coverage_analyzer/bin'))


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _Subprocess(command, failure_msg, **kw):
  _LOGGER.info('Executing command line %s.', command)
  ret = subprocess.call(command, **kw)
  if ret != 0:
    _LOGGER.error(failure_msg)
    raise RuntimeError(failure_msg)


class _ScopedTempDir(object):
  """A utility class for creating a scoped temporary directory."""
  def __init__(self):
    self._path = None

  def Create(self):
    self._path = tempfile.mkdtemp()

  def path(self):
    return self._path

  def __del__(self):
    if self._path:
      shutil.rmtree(self._path)


class _CodeCoverageRunnerBase(object):
  """A worker class to take care of running through instrumentation,
  profiling and coverage generation. This base class expects derived
  classes to implement the following (see class definition for details):

    _InstrumentOneFile(self, file_path)
    _StartCoverageCapture(self)
    _StopCoverageCapture(self)
    _ProcessCoverage(self, output_path)
  """

  _COVERAGE_FILE = 'unittests'

  def __init__(self, build_dir, keep_work_dir):
    build_dir = os.path.abspath(build_dir)
    self._build_dir = build_dir
    self._keep_work_dir = keep_work_dir
    self._work_dir = None
    self._html_dir = os.path.join(self._build_dir, 'cov')

  def __del__(self):
    self._CleanupWorkdir()

  def Run(self):
    """Performs the code coverage capture for all unittests."""
    self._CreateWorkdir()
    try:
      self._CaptureCoverage()
    finally:
      self._CleanupWorkdir()

  def _InstrumentOneFile(self, file_path):
    """Instruments the provided module for coverage, in place.

    Args:
      file_path: The path of the module to be instrumented.
    """
    raise NotImplementedError()

  def _StartCoverageCapture(self):
    """Starts the coverage capture process."""
    raise NotImplementedError()

  def _StopCoverageCapture(self):
    """Stops the coverage capture process."""
    raise NotImplementedError()

  def _ProcessCoverage(self, output_path):
    """Processes coverage results and produces an GCOV/LCOV formatted
    coverage results file in |output_path|.

    Args:
      output_path: The path of the output file to produce.
    """
    raise NotImplementedError()

  def _CreateWorkdir(self):
    assert(self._work_dir == None)
    # The work dir must be a sibling to build_dir, as unittests refer
    # to test data through relative paths from their own executable.
    work_parent = os.path.abspath(os.path.join(self._build_dir, '..'))
    self._work_dir = tempfile.mkdtemp(prefix='instr-', dir=work_parent)
    _LOGGER.info('Created working directory "%s".', self._work_dir)

  def _CleanupWorkdir(self):
    # Clean up our working directory if it still exists.
    work_dir = self._work_dir
    self._work_dir = None

    if not work_dir:
      return

    if self._keep_work_dir:
      _LOGGER.info('Keeping working directory "%s".', work_dir)
    else:
      _LOGGER.info('Removing working directory "%s".', work_dir)
      shutil.rmtree(work_dir, ignore_errors=True)

  def _InstrumentExecutables(self):
    build_dir = self._build_dir
    work_dir = self._work_dir
    _LOGGER.info('Build dir "%s".', build_dir)

    # Copy all unittest related files to work_dir.
    for pattern in _FILE_PATTERNS_TO_COPY:
      files = glob.glob(os.path.join(build_dir, pattern))
      for path in files:
        _LOGGER.info('Copying "%s" to "%s".', path, work_dir)
        if os.path.isdir(path):
          # If the source file is a directory, do a recursive copy.
          dst = os.path.join(work_dir, os.path.basename(path))
          shutil.copytree(path, dst)
        else:
          shutil.copy(path, work_dir)

    # Instrument all EXEs in the work dir.
    for exe in glob.glob(os.path.join(work_dir, '*.exe')):
      self._InstrumentOneFile(exe)

    # And the DLLs we've specified.
    for dll in _DLLS_TO_INSTRUMENT:
      self._InstrumentOneFile(os.path.join(work_dir, dll))

  def _RunUnittests(self):
    unittests = (glob.glob(os.path.join(self._work_dir, '*_unittests.exe')) +
        glob.glob(os.path.join(self._work_dir, '*_tests.exe')))
    print unittests
    for unittest in unittests:
      _LOGGER.info('Running unittest "%s".', unittest)
      _Subprocess(unittest,
                  'Unittests "%s" failed.' % os.path.basename(unittest))

  def _GenerateHtml(self, input_path):
    croc = os.path.abspath(
        os.path.join(_SYZYGY_DIR, '../tools/code_coverage/croc.py'))
    config = os.path.join(_SYZYGY_DIR, 'build/syzygy.croc')

    # The HTML directory is already deleted. Create it now.
    os.makedirs(self._html_dir)

    cmd = [sys.executable, croc,
           '--tree',
           '--config', config,
           '--input', input_path,
           '--html', self._html_dir]

    # The coverage html generator wants to run in the directory
    # containing our src root.
    cwd = os.path.abspath(os.path.join(_SYZYGY_DIR, '../..'))
    _LOGGER.info('Generating HTML report')
    _Subprocess(cmd, 'Failed to generate HTML coverage report.', cwd=cwd)

  def _CaptureCoverage(self):
    # Clean up old coverage results. We do this immediately so that previous
    # coverage results won't still be around if this script fails.
    shutil.rmtree(self._html_dir, ignore_errors=True)

    self._InstrumentExecutables()
    self._StartCoverageCapture()
    try:
      self._RunUnittests()
    finally:
      self._StopCoverageCapture()

    output_path = os.path.join(self._work_dir,
                              '%s.coverage.lcov' % self._COVERAGE_FILE)
    self._ProcessCoverage(output_path)
    self._GenerateHtml(output_path)


class _CodeCoverageRunnerVS(_CodeCoverageRunnerBase):
  """Code coverage runner that uses the Microsoft Visual Studio Team Tools
  instrumenter.
  """

  def __init__(self, build_dir, perf_tools_dir, coverage_analyzer_dir,
               keep_work_dir):
    super(_CodeCoverageRunnerVS, self).__init__(build_dir, keep_work_dir)
    self._perf_tools_dir = os.path.abspath(perf_tools_dir)
    self._coverage_analyzer_dir = os.path.abspath(coverage_analyzer_dir)

  def _InstrumentOneFile(self, file_path):
    cmd = [os.path.join(self._perf_tools_dir, 'vsinstr.exe'),
           '/coverage',
           '/verbose',
           file_path]
    _LOGGER.info('Instrumenting "%s".', file_path)
    _Subprocess(cmd, 'Failed to instrument "%s"' % file_path)

  def _StartCoverageCapture(self):
    cmd = [os.path.join(self._perf_tools_dir, 'vsperfcmd.exe'),
           '/start:coverage',
           '/output:"%s"' % os.path.join(self._work_dir, self._COVERAGE_FILE)]
    _LOGGER.info('Starting coverage capture.')
    _Subprocess(cmd, 'Failed to start coverage capture.')

  def _StopCoverageCapture(self):
    cmd = [os.path.join(self._perf_tools_dir, 'vsperfcmd.exe'), '/shutdown']
    _LOGGER.info('Halting coverage capture.')
    _Subprocess(cmd, 'Failed to stop coverage capture.')

  def _ProcessCoverage(self, output_path):
    # The vsperf tool creates an output with suffix '.coverage'.
    input_path = os.path.join(self._work_dir,
                              '%s.coverage' % self._COVERAGE_FILE)

    # Coverage analyzer will go ahead and place its output in
    # input_file + '.lcov'.
    default_output_path = input_path + '.lcov'

    cmd = [os.path.join(self._coverage_analyzer_dir, 'coverage_analyzer.exe'),
           '-noxml', '-sym_path=%s' % self._work_dir,
           input_path]
    _LOGGER.info('Generating LCOV file.')
    _Subprocess(cmd, 'LCOV generation failed.')

    # Move the default output location if necessary.
    if default_output_path != output_path:
      shutil.move(default_output_path, output_path)


class _CodeCoverageRunnerSyzygy(_CodeCoverageRunnerBase):
  """Code coverage runner that uses the Syzygy code coverage client."""

  _SYZYCOVER = 'syzycover'

  def __init__(self, build_dir, keep_work_dir):
    super(_CodeCoverageRunnerSyzygy, self).__init__(build_dir, keep_work_dir)
    self._temp_dir = _ScopedTempDir()
    self._temp_dir.Create()

  def _InstrumentOneFile(self, file_path):
    temp_path = os.path.join(self._temp_dir.path(),
                             os.path.basename(file_path))
    shutil.copy(file_path, temp_path)
    cmd = [os.path.join(self._build_dir, 'instrument.exe'),
           '--mode=COVERAGE',
           '--agent=%s.dll' % self._SYZYCOVER,
           '--input-image=%s' % temp_path,
           '--output-image=%s' % file_path,
           '--no-augment-pdb',
           '--overwrite']
    _LOGGER.info('Instrumenting "%s".', file_path)
    _Subprocess(cmd, 'Failed to instrument "%s"' % file_path)

  def _StartCoverageCapture(self):
    # Grab a copy of the coverage client and place it in the work directory.
    # We give it a different name so that it doesn't conflict with the
    # instrumented coverage_client.dll.
    syzycover = os.path.abspath(os.path.join(
        self._work_dir, '%s.dll' % self._SYZYCOVER))
    shutil.copy(os.path.join(self._build_dir, 'coverage_client.dll'),
                syzycover)

    # Set up the environment so that the coverage client will connect to
    # the appropriate call trace client. Also make it so that it will crash if
    # the RPC connection is unable to be made.
    os.environ['SYZYGY_RPC_INSTANCE_ID'] = '%s,%s' % (syzycover,
                                                      self._SYZYCOVER)
    os.environ['SYZYGY_RPC_SESSION_MANDATORY'] = '%s,1' % (syzycover)

    # Start an instance of the call-trace service in the background.
    cmd = [os.path.join(self._build_dir, 'call_trace_service.exe'),
           'spawn',
           '--instance-id=%s' % self._SYZYCOVER,
           '--trace-dir=%s' % self._work_dir]
    _LOGGER.info('Starting coverage capture.')
    _Subprocess(cmd, 'Failed to start coverage capture.')

  def _StopCoverageCapture(self):
    cmd = [os.path.join(self._build_dir, 'call_trace_service.exe'),
           'stop',
           '--instance-id=%s' % self._SYZYCOVER]
    _LOGGER.info('Halting coverage capture.')
    _Subprocess(cmd, 'Failed to stop coverage capture.')

  def _ProcessCoverage(self, output_path):
    bin_files = glob.glob(os.path.join(self._work_dir, 'trace-*.bin'))
    _LOGGER.info('Generating LCOV file.')
    cmd = [os.path.join(self._build_dir, 'grinder.exe'),
           '--mode=coverage',
           '--output-file=%s' % output_path] + bin_files
    _Subprocess(cmd, 'LCOV generation failed.')


_USAGE = """\
%prog [options]

Generates a code coverage report for unittests in a given build directory.
On a successful run, the HTML report will be produced in a subdirectory
of the given build directory named "cov".
"""


def _ParseArguments():
  parser = optparse.OptionParser()
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('--build-dir', dest='build_dir',
                    help='The directory where build output is placed.')
  parser.add_option('--target', dest='target',
                    help='The build profile for which coverage is being '
                         'generated. If not specified, default to None. '
                         'Will be appended to --build-dir to generate the '
                         'name of the directory containing the binaries '
                         'to analyze.')
  parser.add_option('--perf-tools-dir', dest='perf_tools_dir',
                    default=_PERF_TOOLS_DIR,
                    help='The directory where the VS performance tools, '
                         '"vsinstr.exe" and "vsperfcmd.exe" are found. '
                         'Ignored if --syzygy is specified.')
  parser.add_option('--coverage-analyzer-dir', dest='coverage_analyzer_dir',
                    default=_COVERAGE_ANALYZER_DIR,
                    help='The directory where "coverage_analyzer.exe" '
                         'is found. Ignored if --syzygy is specified.')
  parser.add_option('--keep-work-dir', action='store_true', default=False,
                    help='Keep temporary directory after run.')
  parser.add_option('--syzygy', action='store_true', default=False,
                    help='Use Syzygy coverage tools.')

  (opts, args) = parser.parse_args()
  if args:
    parser.error('This script does not accept any arguments.')

  if not opts.build_dir:
    parser.error('You must provide a build directory.')
  opts.build_dir = os.path.abspath(opts.build_dir)

  # If a target name was specified, then refine the build path with that.
  if opts.target:
    opts.build_dir = os.path.abspath(os.path.join(opts.build_dir, opts.target))
  if not os.path.isdir(opts.build_dir):
    parser.error('Path does not exist: %s' % opts.build_dir)

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return opts


def main():
  opts = _ParseArguments()

  if opts.syzygy:
    runner = _CodeCoverageRunnerSyzygy(opts.build_dir,
                                       opts.keep_work_dir)
  else:
    runner = _CodeCoverageRunnerVS(opts.build_dir,
                                   opts.perf_tools_dir,
                                   opts.coverage_analyzer_dir,
                                   opts.keep_work_dir)

  runner.Run()


if __name__ == '__main__':
  sys.exit(main())
