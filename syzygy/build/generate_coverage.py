#!python
# Copyright 2012 Google Inc.
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
  'call_trace.dll',
  'call_trace_client.dll',
  'profile_client.dll',
]


_SYZYGY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


# This is hardcoded to the Visual Studio default install location.
_PERF_TOOLS_DIR = ('C:/Program Files (x86)/Microsoft Visual Studio 9.0/'
                   'Team Tools/Performance Tools')


_COVERAGE_ANALYZER_DIR = os.path.normpath(
    os.path.join(_SYZYGY_DIR, '../third_party/coverage_analyzer/bin'))


_LOGGER = logging.getLogger(__name__)


def _Subprocess(command, failure_msg, **kw):
  _LOGGER.info('Executing command line %s.', command)
  ret = subprocess.call(command, **kw)
  if ret != 0:
    _LOGGER.error(failure_msg)
    raise RuntimeError(failure_msg)


class _CodeCoverageRunner(object):
  """A worker class to take care of running through instrumentation,
  profiling and coverage generation."""

  _COVERAGE_FILE = 'unittests'

  def __init__(self, build_dir, perf_tools_dir, coverage_analyzer_dir,
               keep_work_dir):
    build_dir = os.path.abspath(build_dir)
    self._build_dir = build_dir
    self._perf_tools_dir = os.path.abspath(perf_tools_dir)
    self._coverage_analyzer_dir = os.path.abspath(coverage_analyzer_dir)
    self._keep_work_dir = keep_work_dir
    self._work_dir = None

  def __del__(self):
    self._CleanupWorkdir()

  def Run(self):
    """Performs the code coverage capture for all unittests."""
    self._CreateWorkdir()
    try:
      self._CaptureCoverage()
    finally:
      self._CleanupWorkdir()

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

    # Make a copy of all unittest executables, DLLs, PDBs and test_data in
    # the build directory.
    for pattern in ('*_unittests.exe', '*.dll', '*.pdb', 'test_data'):
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

  def _RunUnittests(self):
    unittests = glob.glob(os.path.join(self._work_dir, '*_unittests.exe'))
    print unittests
    for unittest in unittests:
      _LOGGER.info('Running unittest "%s".', unittest)
      _Subprocess(unittest,
                  'Unittests "%s" failed.' % os.path.basename(unittest))

  def _ProcessCoverage(self):
    coverage_file = os.path.join(self._work_dir,
                                 '%s.coverage' % self._COVERAGE_FILE)
    cmd = [os.path.join(self._coverage_analyzer_dir, 'coverage_analyzer.exe'),
           '-noxml', '-sym_path=%s' % self._work_dir,
           coverage_file]
    _LOGGER.info('Generating LCOV file.')
    _Subprocess(cmd, 'LCOV generation failed.')

  def _GenerateHtml(self):
    croc = os.path.abspath(
        os.path.join(_SYZYGY_DIR, '../tools/code_coverage/croc.py'))
    config = os.path.join(_SYZYGY_DIR, 'build/syzygy.croc')
    input = os.path.join(self._work_dir,
                         '%s.coverage.lcov' % self._COVERAGE_FILE)
    html = os.path.join(self._build_dir, 'cov')

    # Clean up old coverage results.
    shutil.rmtree(html, ignore_errors=True)
    os.makedirs(html)

    cmd = [sys.executable, croc,
           '--tree',
           '--config', config,
           '--input', input,
           '--html', html]

    # The coverage html generator wants to run in the directory
    # containing our src root.
    cwd = os.path.abspath(os.path.join(_SYZYGY_DIR, '../..'))
    _LOGGER.info('Generating HTML report')
    _Subprocess(cmd, 'Failed to generate HTML coverage report.', cwd=cwd)

  def _CaptureCoverage(self):
    self._InstrumentExecutables()
    self._StartCoverageCapture()
    try:
      self._RunUnittests()
    finally:
      self._StopCoverageCapture()

    self._ProcessCoverage()
    self._GenerateHtml()


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
  parser.add_option('', '--build-dir', dest='build_dir',
                    help='The directory containing the build to generate '
                         'a code coverage report for.')
  parser.add_option('', '--perf-tools-dir', dest='perf_tools_dir',
                    default=_PERF_TOOLS_DIR,
                    help='The directory where the VS performance tools, '
                         '"vsinstr.exe" and "vsperfcmd.exe" are found.')
  parser.add_option('', '--coverage-analyzer-dir', dest='coverage_analyzer_dir',
                    default=_COVERAGE_ANALYZER_DIR,
                    help='The directory where "coverage_analyzer.exe" '
                         'is found.')
  parser.add_option('', '--keep-work-dir', action='store_true', default=False,
                    help='Keep temporary directory after run.')

  (opts, args) = parser.parse_args()
  if args:
    parser.error('This script does not accept any arguments.')
  if not opts.build_dir:
    parser.error('You must provide a build directory.')
  opts.build_dir = os.path.abspath(opts.build_dir)

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return opts


def main():
  opts = _ParseArguments()
  runner = _CodeCoverageRunner(opts.build_dir,
                               opts.perf_tools_dir,
                               opts.coverage_analyzer_dir,
                               opts.keep_work_dir)
  runner.Run()


if __name__ == '__main__':
  sys.exit(main())
