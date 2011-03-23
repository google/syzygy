#!/usr/bin/python2.4
#
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

"""Utilities to run a test app before and after reordering a binary."""

# Standard modules
import contextlib
import optparse
import os
import re
import shutil
import subprocess
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
               test_program=None, test_arguments=None):
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
    """
    self._reorder_tool = reorder_tool
    self._input_bin = os.path.abspath(input_bin)
    self._input_pdb = os.path.abspath(input_pdb)
    self._test_program = test_program or self._input_bin
    self._test_arguments = test_arguments or []

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

  def _GetExpandedArgs(self, run_id, seed):
    """Expand any placeholders in the test arguments.

    Currently we support the run_id and the seed, via an adhoc substition.

    Args:
      run_id: An identifier denoting the current iteration
      seed: The value denoting the seed for the random reordering

    Returns:
      A new list of arguments, with placeholders expanded as appropriate.
    """
    return [
        arg.replace('{iter}', '%03d' % run_id).replace('{seed}', '%s' % seed)
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
    test_dir, test_name = os.path.split(self._test_program)
    _LOGGER.info('run=%s; Running %s ...', run_id, test_name)
    with WorkingDirectory(test_dir):
      command = [self._test_program] + self._GetExpandedArgs(run_id, seed)
      proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
      while proc.poll() is None:
        test, status = self._ParseResultLine(proc.stdout.readline(), run_id)
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
        '--input-dll=%s' % self._input_bin,
        '--input-pdb=%s' % self._input_pdb,
        '--output-dll=%s' % new_bin,
        '--output-pdb=%s' % new_pdb,
        ]
    _LOGGER.info(
        'run=%s; Rewriting %s', run_id, os.path.basename(self._input_bin))
    _LOGGER.info('run=%s; Using random seed = %s', run_id, seed)

    with WorkingDirectory(os.path.dirname(self._reorder_tool)):
      proc = subprocess.Popen(
          command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      output = []
      while proc.poll() is None:
        line = proc.stdout.readline().strip()
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
    """Compare the pre and post results in for each test in result_map.

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

    # if either result set is empty, then there's a problem
    was_successful = True if (orig_results and new_results) else False

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

  def Run(self, seed=None, num_iterations=1):
    """Repeatedly run the reorder test.

    Args:
      seed: The first seed to use, subsequent seeds will be automatically
          generated based on the current time.  This value is expected to
          be an integer, or None.
      num_iterations: The total number of iterations of the reorder/test
          sequence to run.

    Returns:
      A pair of integers denoting the number of passed and failed tests,
      respectively.
    """
    orig_results = self.RunTestApp(0, 'unmodified')
    passed, failed = 0, 0
    for counter in xrange(1, num_iterations + 1):
      self.ReorderBinary(counter, seed)
      try:
        new_results = self.RunTestApp(counter, seed)
        if self.CompareResults(counter, orig_results, new_results):
          _LOGGER.info('run=%s; Test results matched!', counter)
          passed += 1
        else:
          _LOGGER.error('run=%s; Test results did NOT match!', counter)
          failed += 1
      finally:
        self.RevertBinary()
      seed = int(time.time())
    return passed, failed


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
      '--reorder-seed', type='int', metavar='NUM', default=int(time.time()),
      help='Seed for the initial random reordering iteration')
  group.add_option(
      '--reorder-num-iterations', type='int', default=1, metavar='NUM',
      help='The number of reorder iterations to run (default: %default)')
  option_parser.add_option_group(group)


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
  options.reorder_tool = os.path.abspath(options.reorder_tool)
  options.reorder_input_bin = os.path.abspath(options.reorder_input_bin)
  options.reorder_input_pdb = os.path.abspath(options.reorder_input_pdb)
  options.reorder_test_program = os.path.abspath(options.reorder_test_program)

def ParseArgs():
  """Parse the command line options and additional test arguments."""
  option_parser = optparse.OptionParser(
      'Usage: %prog [options] [-- test-app-options]')
  AddCommandLineOptions(option_parser)
  log_helper.AddCommandLineOptions(option_parser)
  options, test_args = option_parser.parse_args()
  ValidateCommandLineOptions(option_parser, options)
  return options, test_args

def GetSummaryLine(passed, failed):
  """Summarize the number of iterations which passed and failed.

  Args:
    passed: The number of iterations that passed
    failed: The number of iterations that failed
  """
  return 'Reorder Test Results (%s passed, %s failed)' % (passed, failed)

def main():
  """Main script function."""
  options, reorder_test_args = ParseArgs()
  log_helper.InitLogger(options)
  test = ReorderTest(options.reorder_tool,
                     options.reorder_input_bin, options.reorder_input_pdb,
                     options.reorder_test_program, reorder_test_args)
  passed, failed = test.Run(seed=options.reorder_seed,
                            num_iterations=options.reorder_num_iterations)
  print GetSummaryLine(passed, failed)

if __name__ == '__main__':
  main()
