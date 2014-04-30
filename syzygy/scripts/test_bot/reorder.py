#!/usr/bin/python2.4
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

"""Utilities to run a test app before and after reordering a binary."""

# Standard modules
import contextlib
import glob
import optparse
import os
import re
import shutil
import subprocess
import sys
import time

# Local modules
import log_helper


# Private logger object for this library
_LOGGER = log_helper.GetLogger(__file__)


@contextlib.contextmanager
def WorkingDirectory(path):
  """Creates a context manager for running code in a given working directory.

  Args:
    path: The working directory to set.

  Returns:
    A with_statement context manager that sets the current work directory to
    path on entry to the block and returns to the previous working directory
    after the block.
  """
  cwd = os.getcwd()
  try:
    os.chdir(path)
    yield
  finally:
    os.chdir(cwd)


class ReorderTest(object):
  """Runs multiple test iterations before and after reordering a binary."""

  _RESULT_FILTER_RE = re.compile(
     r'\[\s+(?P<status>OK|FAILED)\s+\]\s+(?P<test>\w+\.\w+)')

  def __init__(self, reorder_tool, input_bin, input_pdb,
               test_program=None, test_arguments=None, padding=None,
               reorder_basic_blocks=False):
    """Initializes an instance of the reorder test.

    Args:
      reorder_tool: The path to the reordering tool.  If a relative
          path is given, it will be converted to an absolute path.
      input_bin: The path to the exe of dll which will be reordered.
          If a relative path is given, it will be converted to
          an absolute path.
      input_pdb: The path to the PDB file corresponding to bin.
          If a relative path is given, it will be converted to
          an absolute path.
      test_program: The test program to run before and after reordering.
          If not provided, this will default to the input bin path.
          If a relative path is given, it will be converted to
          an absolute path.
      test_arguments: A list or arguments to provide when running the
          test_program.  If not provided, no additional arguments will
          be given.
      padding: The amount of padding to put between blocks.
      reorder_basic_blocks: True if the randomization should take place
          at the basic block level (as opposed to at the code/data block
          level). This defaults to false.
    """
    self._reorder_tool = reorder_tool
    self._input_bin = os.path.abspath(input_bin)
    self._input_pdb = os.path.abspath(input_pdb)
    self._test_program = test_program or self._input_bin
    self._test_arguments = test_arguments or []
    self._padding = padding or 0
    self._reorder_basic_blocks = reorder_basic_blocks

  def _ParseResultLine(self, line, run_id):
    """Parse a line of output from the test app.

    Args:
      line: the line of output.
      run_id: an identifier for the run (used for logging).

    Returns:
      If the line of output denotes a test result, this function returns
      a pair comprising the name of the test and the status (OK of FAILED)
      of the test; otherwise, it returns the pair (None, None)
    """
    line = line.strip()
    match = self._RESULT_FILTER_RE.match(line)
    if not match:
      if line:
        _LOGGER.debug('run=%s; %s', run_id, line)
      return None, None
    test = match.group('test')
    status = match.group('status')
    _LOGGER.info('run=%s; [ %8s ] %s', run_id, status, test)
    return test, status

  def _GetPaths(self, name):
    """Generates directory, binary, and pdb file paths.

    For example, to generate "backup" paths if the original input bin
    and pdb paths were C:\foo\bar.dll and C:\baz\bar.pdb you call
    reorder_test._GetPaths('backup') which returns:

      (r'C:\foo\backup\',r'C:\foo\backup\bar.dll', r'C:\foo\backup\bar.pdb')

    Args:
      name: The discrimating name to use when generating the paths

    Returns:
      A triple of the root directory, the new binary file, and the new pdb
      file paths.
    """
    bin_path, bin_name = os.path.split(self._input_bin)
    dir_path = os.path.join(bin_path, name)
    bin_path = os.path.join(dir_path, bin_name)
    pdb_path = os.path.join(dir_path, os.path.basename(self._input_pdb))
    return dir_path, bin_path, pdb_path

  def _GetExpandedArgs(self, bin_dir, run_id, seed):
    """Expand any placeholders in the test arguments.

    Currently we support bin_dir, run_id and seed, via an adhoc substition.

    Args:
      bin_dir: The directory containing the instrumented binary.
      run_id: An identifier denoting the current iteration
      seed: The value denoting the seed for the random reordering

    Returns:
      A new list of arguments, with placeholders expanded as appropriate.
    """
    return [
        arg.replace('{bin_dir}', '%s' % bin_dir) \
            .replace('{iter}', '%03d' % run_id) \
            .replace('{seed}', '%s' % seed)
        for arg in self._test_arguments]

  def RunTestApp(self, run_id, seed):
    """Run the test program and capture the status of each test.

    The results (a before and after pair) are added to the result map
    using the name of the test as the dictionary key and a pair of
    strings as the value.

    Args:
      run_id: Used when logging about this invocation of the test.
      seed: The value denoting the seed for the random reordering.
          Used for logging purposes.

    Returns:
      A dictionary mapping test names to result strings.
    """
    results = {}
    bin_dir = os.path.dirname(self._input_bin)
    test_dir, test_name = os.path.split(self._test_program)
    _LOGGER.info('run=%s; Running %s ...', run_id, test_name)
    with WorkingDirectory(test_dir):
      command = [self._test_program] + self._GetExpandedArgs(
          bin_dir, run_id, seed)
      proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
      while True:
        line = proc.stdout.readline().strip()
        if proc.poll() is not None and not line:
          break
        test, status = self._ParseResultLine(line, run_id)
        if test:
          results[test] = status

    _LOGGER.info('run=%s; Finished running %s', run_id, test_name)
    return results

  def ReorderBinary(self, run_id, seed=None):
    """Replaces the original input binary with a randomly reordered binary.

    Args:
      run_id: An identifier denoting the current iteration
      seed: An integer value to seed the random generator for the reorder
    """
    if seed is None:
      seed = int(time.time())

    new_dir, new_bin, new_pdb = self._GetPaths('seed-%s' % seed)
    if not os.path.exists(new_dir):
      os.makedirs(new_dir)

    command = [
        self._reorder_tool,
        '--seed=%s' % seed,
        '--input-image=%s' % self._input_bin,
        '--input-pdb=%s' % self._input_pdb,
        '--output-image=%s' % new_bin,
        '--output-pdb=%s' % new_pdb,
        '--padding=%s' % self._padding,
        '--fuzz',
        '--verbose=1',
        '--no-augment-pdb',
        ]
    if self._reorder_basic_blocks:
      command.append('--basic-blocks')
    _LOGGER.info(
        'run=%s; Rewriting %s', run_id, os.path.basename(self._input_bin))
    _LOGGER.info('run=%s; Using random seed = %s', run_id, seed)
    _LOGGER.info('run=%s; Using padding length = %s', run_id, self._padding)
    _LOGGER.info(
        'run=%s; Reorder basic blocks = %s', run_id, self._reorder_basic_blocks)

    with WorkingDirectory(os.path.dirname(self._reorder_tool)):
      proc = subprocess.Popen(
          command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      output = []
      while True:
        line = proc.stdout.readline().strip()
        if proc.poll() is not None and not line:
          break
        if line:
          _LOGGER.debug('run=%s; %s', run_id, line)
          output.append(line)

    if proc.returncode != 0:
      raise Exception('\n'.join(output))

    # Backup the original (input) binary and pdb files.
    backup_dir, backup_bin, backup_pdb = self._GetPaths('orig')
    _LOGGER.info(
        'run=%s; Moving original input files to %s', run_id, backup_dir)
    if not os.path.exists(backup_dir):
      os.makedirs(backup_dir)
    shutil.move(self._input_bin, backup_bin)
    shutil.move(self._input_pdb, backup_pdb)

    # Copy the new binary and pdb files to the location of the originals.
    _LOGGER.info('run=%s; Placing reordered files', run_id)
    shutil.copyfile(new_bin, self._input_bin)
    shutil.copyfile(new_pdb, self._input_pdb)

    _LOGGER.info('run=%s; Finished reordering binary', run_id)

  def RevertBinary(self):
    """Moves the backed-up input files to their original locations."""
    backup_dir, backup_bin, backup_pdb = self._GetPaths('orig')
    if os.path.exists(backup_bin):
      _LOGGER.info('Restoring %s from %s', self._input_bin, backup_dir)
      shutil.move(backup_bin, self._input_bin)
    if os.path.exists(backup_pdb):
      _LOGGER.info('Restoring %s from %s', self._input_pdb, backup_dir)
      shutil.move(backup_pdb, self._input_pdb)

  @staticmethod
  def CompareResults(run_id, orig_results, new_results):
    """Compare the pre and post results for each test in result_map.

    Args:
      orig_results: a dictionary of test names -> result strings
      new_results: a dictionary of test names -> result strings

    Returns:
      True iff all orig_results and new_results have the same non-empty
      set of tests and the results for each test match.
    """
    merged_results = {}

    for test, result in orig_results.iteritems():
      # Capture the orignal result, but no result yet for the new
      # Use a list so we can update the new result later.
      merged_results[test] = [result, None]

    for test, result in new_results.iteritems():
      # use setdefault to catch the case where a test is in the
      # new result but not the original result, which would be odd.
      merged_results.setdefault(test, [None, None])[1] = result

    was_successful = True

    # We go through all the results mostly so we can log the
    # output.  Otherwise, we could have just done an equality
    # comparison between the input dictionaries.
    before, after = 0, 1
    for test, results in merged_results.iteritems():
      if results[before] != results[after]:
        is_flaky = test.split('.', 1)[1].startswith('FLAKY_')
        log_func = is_flaky and _LOGGER.warning or _LOGGER.error
        was_successful &= is_flaky
        log_func('run=%s; %s: %s -> %s', run_id, test, results[before],
                 results[after])

    return was_successful

  def Run(self, seed=None, num_iterations=1, max_attempts=3,
          revert_binaries=True):
    """Repeatedly run the reorder test.

    Args:
      seed: The first seed to use, subsequent seeds will be automatically
          generated based on the current time.  This value is expected to
          be an integer, or None.
      num_iterations: The total number of iterations of the reorder/test
          sequence to run.
      max_attempts: The maximum number of time to try running the test
          application if the results do not match the initial control
          result set.
      revert_binaries: If True (the default) the original values will be
          restored after running the test app, otherwise, the reordered
          binaries will be left in place of the originals.

    Returns:
      A pair of integers denoting the number of passed and failed tests,
      respectively.
    """
    # Establish the baseline results by running the test multiple times.
    # If the candidate control run does not consistently pass all the
    # tests, we abandon this test run as flaky.
    control_results = None
    for attempt in xrange(1, max_attempts + 1):
      _LOGGER.info('run=%s; attempt=%s/%s; Launching test app ...',
                   0, attempt, max_attempts)
      results = self.RunTestApp(0, 'unmodified')
      if not all(result == 'OK' for result in results.itervalues()):
        _LOGGER.error('Running the unmodified test binaries failed!')
        return 0, 0
      if control_results is None:
        control_results = results
      elif results != control_results:
        _LOGGER.error(
            'Inconsistent "successful" results from the unmodified binaries!')
        return 0, 0
    _LOGGER.info('Established baseline results.')

    # Run the reorder test num_iterations times. For each iteration, make up
    # to max_attempts tries to get matching results before declaring the
    # iteration a failure.
    passed, failed = 0, 0
    for counter in xrange(1, num_iterations + 1):
      self.ReorderBinary(counter, seed)
      try:
        status = 0
        for attempt in xrange(1, max_attempts + 1):
          _LOGGER.info('run=%s; attempt=%s/%s; Launching test app ...',
                       counter, attempt, max_attempts)
          new_results = self.RunTestApp(counter, seed)
          if self.CompareResults(counter, control_results, new_results):
            _LOGGER.info('run=%s; attempt=%s; Test results matched!',
                         counter, attempt)
            status = 1
            break
          _LOGGER.error('run=%s; attempt=%s/%s; Test results did NOT match!',
                        counter, attempt, max_attempts)
        passed += status
        failed += (1 - status)
      finally:
        if revert_binaries:
          self.RevertBinary()
      seed = int(time.time())
    return passed, failed


# We artificaially cap padding at 1024 bytes, but that's really big and
# would bloat the binary.  Internally, the real limit of the reorder tool
# is much larger (on the order of a page or two).
_MAX_PADDING = 1024
_SAFEST_ALIGNMENT = 8


def _PaddingHandler(option, dummy_opt, value, parser):
  """Validates the parameter to the reorder-padding parameter."""
  if value > _MAX_PADDING or value % _SAFEST_ALIGNMENT != 0:
    raise optparse.OptionValueError('Invalid padding value')
  setattr(parser.values, option.dest, value)


def AddCommandLineOptions(option_parser):
  """Adds command line options to the given OptionsParser."""
  group = optparse.OptionGroup(option_parser, 'Reordering and Test Options')
  group.add_option(
      '--reorder-tool', metavar='EXE', help='Path to the reordering tool')
  group.add_option(
      '--reorder-input-bin', metavar='EXE_OR_DLL',
      help='Path to EXE or DLL file to be reordered')
  group.add_option(
      '--reorder-input-pdb', metavar='PDB',
      help='Path to correspoinding PDB file for EXE_OR_DLL')
  group.add_option(
      '--reorder-test-program', metavar='EXE',
      help='Path to test executable to run, if different from EXE_OR_DLL')
  group.add_option(
      '--reorder-basic-blocks', action='store_true', default=False,
      help='Reorder at the basic block level')
  group.add_option(
      '--reorder-seed', type='int', metavar='NUM', default=int(time.time()),
      help='Seed for the initial random reordering iteration')
  group.add_option(
      '--reorder-padding', type='int', metavar='NUM', action='callback',
      callback=_PaddingHandler, nargs=1, callback_args=(), callback_kwargs={},
      help='The number of padding bytes to insert between blocks (default: '
          '%%default). This value should be a multiple of %d and less than '
          'or equal to %d, to preserve data alignment and avoid excessively '
          'bloating the reordered binary.' % (_SAFEST_ALIGNMENT, _MAX_PADDING))
  group.add_option(
      '--reorder-num-iterations', type='int', default=1, metavar='NUM',
      help='The number of reorder iterations to run (default: %default)')
  group.add_option(
      '--reorder-max-test-attempts', type='int', default=3, metavar='NUM',
      help='The maximum number of attempts to run the tests before giving up.')
  group.add_option(
      '--reorder-no-revert-binaries', action='store_true', default=False,
      help=('Do not to revert the input binaries after running the reordering '
            '(to revert is the default behaviour). This option requires that '
            'the number of iterations be 1 (the default).'))
  option_parser.add_option_group(group)


def _FindInputFileByPattern(pattern, parser):
  """Returns the unique input file matching pattern.

  If no unique matching file exist this invokes parser.error()
  """
  matches = glob.glob(pattern)
  if len(matches) != 1:
    return parser.error('No unique file matching "%s" was found.' % pattern)
  return os.path.abspath(matches[0])


def ValidateCommandLineOptions(option_parser, options):
  """Ensures that all required parameters are counter for.

  Args:
    option_parser: The option parser which was used to extract the options
        from the command line.  This is used to generate error messages if
        necessary.
    options: The options that have been extracted from the command line.
  """
  if not options.reorder_test_program:
    options.reorder_test_program = options.reorder_input_bin
  if not options.reorder_tool:
    option_parser.error('--reorder-tool is required')
  if not options.reorder_input_bin:
    option_parser.error('--reorder_input-bin is required')
  if not options.reorder_input_pdb:
    option_parser.error('--reorder_input-pdb is required')
  if (options.reorder_num_iterations != 1 and
      options.reorder_no_revert_binaries):
    option_parser.error('For now you must revert binaries between iterations.')

  options.reorder_tool = _FindInputFileByPattern(
      options.reorder_tool, option_parser)
  options.reorder_input_bin = _FindInputFileByPattern(
      options.reorder_input_bin, option_parser)
  options.reorder_input_pdb = _FindInputFileByPattern(
      options.reorder_input_pdb, option_parser)
  options.reorder_test_program = _FindInputFileByPattern(
      options.reorder_test_program, option_parser)


def ParseArgs():
  """Parse the command line options and additional test arguments."""
  option_parser = optparse.OptionParser(
      'Usage: %prog [options] [-- test-app-options]')
  option_parser.add_option(
      '--summary-title', default="Reorder Test Results",
      help="The title to attach to the summary message")
  AddCommandLineOptions(option_parser)
  log_helper.AddCommandLineOptions(option_parser)
  options, test_args = option_parser.parse_args()
  ValidateCommandLineOptions(option_parser, options)
  return options, test_args


def GetSummaryLine(title, passed, failed):
  """Summarize the number of iterations which passed and failed.

  Args:
    title: The title for the summary line.
    passed: The number of iterations that passed.
    failed: The number of iterations that failed.
  """
  if passed == 0 and failed == 0:
    return '%s aborted!' % title
  return '%s (%s passed, %s failed)' % (title, passed, failed)


def main():
  """Main script function."""
  if sys.platform == 'win32':
    # Don't show error dialog boxes on crashes or debug-breaks. This setting
    # is inherited by child processes, so a crash in the relinker shouldn't
    # block the tests waiting in a just-in-time debugging dialog box.
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(3)
  options, reorder_test_args = ParseArgs()
  log_helper.InitLogger(options)
  test = ReorderTest(
      options.reorder_tool,
      options.reorder_input_bin, options.reorder_input_pdb,
      test_program=options.reorder_test_program,
      test_arguments=reorder_test_args,
      padding=options.reorder_padding,
      reorder_basic_blocks=options.reorder_basic_blocks)
  passed, failed = test.Run(
      seed=options.reorder_seed,
      num_iterations=options.reorder_num_iterations,
      max_attempts=options.reorder_max_test_attempts,
      revert_binaries=not options.reorder_no_revert_binaries)
  print GetSummaryLine(options.summary_title, passed, failed)


if __name__ == '__main__':
  sys.exit(main())
