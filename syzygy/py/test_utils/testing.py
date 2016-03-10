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

"""Defines a collection of classes for running unit-tests."""

import cStringIO
import datetime
import hashlib
import logging
import optparse
import os
import presubmit
import re
import subprocess
import sys
import temp_watcher


_LOGGER = logging.getLogger(os.path.basename(__file__))


class Error(Exception):
  """An error class used for reporting problems while running tests."""
  pass


class RunFailure(Error):
  """The error thrown to indicate that a sub-command has failed."""
  pass


class TestFailure(Error):
  """An error that can be thrown to indicate that a test has failed."""
  pass


def AddThirdPartyToPath():
  """Drags in the colorama module from third party."""
  third_party = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             '..', '..', '..', 'third_party'))
  if third_party not in sys.path:
    sys.path.insert(0, third_party)


AddThirdPartyToPath()
import colorama


def RunCommand(cmd, *args, **kwargs):
  """Runs the provided command using subprocess.

  Args:
    cmd: The command to be run, as a list.

  Returns:
    A tuple of (stdout, stderr).

  Raises:
    RunFailure: If the command fails.
  """
  _LOGGER.debug('Running %s.', cmd)
  popen = subprocess.Popen(cmd, *args, **kwargs)
  (stdout, stderr) = popen.communicate()
  if popen.returncode != 0:
    raise RunFailure('Command %s failed with return code %d.' %
        (cmd, popen.returncode))
  return (stdout, stderr)


class Test(object):
  """A base class embodying the notion of a test. A test has a name, and is
  invokable by calling 'Run' with a given configuration. Upon success, the
  test will create a success file in the appropriate configuration
  directory.

  The 'Main' routine of any Test object may also be called to have it
  run as as stand-alone command line test.
  """

  def __init__(self, build_dir, name, leaf):
    """Initializes this test.

    Args:
      build_dir: The root build output directory.
      name: The name of this test.
      leaf: If true this test is a leaf. That is, it actually runs an
          executable. Otherwise it is a non-leaf test that simply aggregates
          results from other tests.
    """

    self._build_dir = build_dir
    self._name = name
    self._force = False
    self._leaf = leaf

    # Tests are to direct all of their output to these streams.
    # NOTE: These streams aren't directly compatible with subprocess.Popen.
    self._stdout = cStringIO.StringIO()
    self._stderr = cStringIO.StringIO()

  def GetSuccessFilePath(self, configuration):
    """Returns the path to the success file associated with this test."""
    success_path = presubmit.GetTestSuccessPath(self._build_dir,
                                                configuration,
                                                self._name)
    return success_path

  def LastRunTime(self, configuration):
    """Returns the time this test was last run in the given configuration.
    Returns 0 if the test has no success file (equivalent to never having
    been run).
    """
    try:
      return os.stat(self.GetSuccessFilePath(configuration)).st_mtime
    except (IOError, WindowsError):
      return 0

  def _CanRun(self, configuration):  # pylint: disable=R0201,W0613
    """Indicates whether this test can run the given configuration.

    Derived classes may override this in order to indicate that they
    should not be run in certain configurations. This stub always returns
    True.

    If the derived class wants to indicate that the test has failed it can
    also raise a TestFailure error here.

    Args:
      configuration: the configuration to test.

    Returns:
      True if this test can run in the given configuration, False otherwise.

    Raises:
      TestFailure if the test should be considered as failed.
    """
    return True

  def _NeedToRun(self, configuration):  # pylint: disable=R0201,W0613
    """Determines whether this test needs to be run in the given configuration.

    Derived classes may override this if they can determine ahead of time
    whether the given test needs to be run. This stub always returns True.

    If the derived class wants to indicate that the test has failed it can
    also raise a TestFailure error here.

    Args:
      configuration: the configuration to test.

    Returns:
      True if this test can run in the given configuration, False otherwise.

    Raises:
      TestFailure if the test should be considered as failed.
    """
    return True

  def _MakeSuccessFile(self, configuration):
    """Makes the success file corresponding to this test in the given
    configuration.
    """
    success_path = self.GetSuccessFilePath(configuration)
    _LOGGER.debug('Creating success file "%s".',
                  os.path.relpath(success_path, self._build_dir))
    success_file = open(success_path, 'wb')
    success_file.write(str(datetime.datetime.now()))
    success_file.close()

  def _Touch(self, configuration):
    """This is as a stub of the functionality that must be implemented by
    child classes.

    Args:
      configuration: the configuration of the test to touch.
    """

  def _Run(self, configuration):
    """This is as a stub of the functionality that must be implemented by
    child classes.

    Args:
      configuration: the configuration in which to run the test.

    Returns:
      True on success, False on failure. If a test fails by returning False
      all of the others test will continue to run. If an exception is raised
      then all tests are stopped."""
    raise NotImplementedError('_Run not overridden.')

  def _WriteStdout(self, value):
    """Appends a value to stdout.

    Args:
      value: the value to append to stdout.
    """
    self._stdout.write(value)
    return

  def _WriteStderr(self, value):
    """Appends a value to stderr.

    Args:
      value: the value to append to stderr.
    """
    self._stderr.write(value)
    return

  def _GetStdout(self):
    """Returns any accumulated stdout, and erases the buffer."""
    stdout = self._stdout.getvalue()
    self._stdout = cStringIO.StringIO()
    return stdout

  def _GetStderr(self):
    """Returns any accumulated stderr, and erases the buffer."""
    stderr = self._stderr.getvalue()
    self._stderr = cStringIO.StringIO()
    return stderr

  def Touch(self, configuration):
    """Touches the test success file for the test in the given configuration.

    Args:
      configuration: The configuration to touch.
    """
    self._Touch(configuration)
    self._MakeSuccessFile(configuration)

  def Run(self, configuration, force=False):
    """Runs the test in the given configuration. The derived instance of Test
    must implement '_Run(self, configuration)', which raises an exception on
    error or does nothing on success. Upon success of _Run, this will generate
    the appropriate success file. If the test fails, the exception is left
    to propagate.

    Args:
      configuration: The configuration in which to run.
      force: If True, this will force the test to re-run even if _NeedToRun
          would return False.

    Returns:
      True on success, False otherwise.
    """
    # Store optional arguments in a side-channel, so as to allow additions
    # without changing the _Run/_NeedToRun/_CanRun API.
    self._force = force

    success = True
    try:
      if not self._CanRun(configuration):
        _LOGGER.info('Skipping test "%s" in invalid configuration "%s".',
                     self._name, configuration)
        return True

      # Always run _NeedToRun, even if force is true. This is because it may
      # do some setup work that is required prior to calling _Run.
      _LOGGER.debug('Checking to see if we need to run test "%s" in '
                    'configuration "%s".', self._name, configuration)
      need_to_run = self._NeedToRun(configuration)

      if need_to_run:
        _LOGGER.info('Running test "%s" in configuration "%s".',
                     self._name, configuration)
      else:
        _LOGGER.debug('No need to re-run test "%s" in configuration "%s".',
                      self._name, configuration)

      if not need_to_run and force:
        _LOGGER.info('Forcing re-run of test "%s" in configuration "%s".',
                     self._name, configuration)
        need_to_run = True

      if need_to_run:
        if not self._Run(configuration):
          raise TestFailure('Test "%s" failed in configuration "%s".' %
                                (self._name, configuration))

      self._MakeSuccessFile(configuration)
    except TestFailure, e:
      fore = colorama.Fore
      style = colorama.Style
      self._WriteStdout(style.BRIGHT + fore.RED + str(e) + '\n' +
                            style.RESET_ALL)
      success = False
    finally:
      # Forward the stdout, which we've caught and stuffed in a string.
      sys.stdout.write(self._GetStdout())

    return success

  @staticmethod
  def _GetOptParser():
    """Builds an option parser for this class. This function is static as
    it may be called by the constructor of derived classes before the object
    is fully initialized. It may also be overridden by derived classes so that
    they may augment the option parser with additional options.
    """
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', dest='configs',
                      action='append', default=[],
                      help='The configuration in which you wish to run '
                           'this test. This option may be invoked multiple '
                           'times. If not specified, defaults to '
                           '["Debug", "Release"].')
    parser.add_option('-f', '--force', dest='force',
                      action='store_true', default=False,
                      help='Force tests to re-run even if not necessary.')
    parser.add_option('-t', '--touch', dest='touch',
                      action='store_true', default=False,
                      help='Touch the test outputs to make as if they have '
                           'succeeded.')
    parser.add_option('--verbose', dest='log_level', action='store_const',
                      const=logging.DEBUG, default=logging.INFO,
                      help='Run the script with verbose logging.')
    return parser

  def Main(self):
    t1 = datetime.datetime.now()
    colorama.init()

    opt_parser = self._GetOptParser()
    options, dummy_args = opt_parser.parse_args()

    if options.force and options.touch:
      opt_parser.error("--force and --touch don't go together, pick one.")

    logging.basicConfig(level=options.log_level)

    # If no configurations are specified, run all configurations.
    if not options.configs:
      options.configs = ['Debug', 'Release']

    result = 0
    for config in set(options.configs):
      # We don't catch any exceptions that may be raised as these indicate
      # something has gone really wrong, and we want them to interrupt further
      # tests.
      if options.touch:
        self.Touch(config)
      elif not self.Run(config, force=options.force):
        _LOGGER.error('Configuration "%s" of test "%s" failed.',
                      config, self._name)
        result = 1

    # Now dump all error messages.
    sys.stdout.write(self._GetStderr())

    t2 = datetime.datetime.now()
    _LOGGER.info('Unittests took %s to run.', t2 - t1)

    return result


class ExecutableTest(Test):
  """An executable test is a Test that is run by launching a single
  executable file, and inspecting its return value.
  """

  def __init__(self, build_dir, name, extra_args=None):
    """Initializes this object.

    Args:
      build_dir: The build output directory.
      name: The name of the executable being testing, without an extension.
          The binary will be looked for in the following location:
              <build_dir>/<build_configuration>/<name>.exe
      extra_args: Extra arguments that will be used when invoking the
          executable. If these are specified the test name (used for generating
          the success file) will be decorated to reflect the contents of the
          extra arguments.
    """
    if extra_args is None:
      extra_args = []

    Test.__init__(self, build_dir, name, True)
    self._extra_args = extra_args

  def _GetTestPath(self, configuration):
    """Returns the path to the test executable. This stub may be overridden,
    but it defaults to self._build_dir/<build_configuration>/<name>.exe
    """
    return os.path.join(
        self._build_dir, configuration, '%s.exe' % self._name)

  def _NeedToRun(self, configuration):
    test_path = self._GetTestPath(configuration)
    if not os.path.exists(test_path):
      return True
    return os.stat(test_path).st_mtime > self.LastRunTime(configuration)

  def _GetCmdLine(self, configuration):
    """Returns the command line to run."""
    return [self._GetTestPath(configuration)] + self._extra_args


  def _Run(self, configuration):
    test_path = self._GetTestPath(configuration)

    # Run the executable. We do this using a 'temp_watcher' Popen wrapper
    # which redirects and monitors the temp directory.
    command = self._GetCmdLine(configuration)
    popen = temp_watcher.Popen(command,
                               cleanup=True,
                               fail=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    (stdout, dummy_stderr) = popen.communicate()
    self._WriteStdout(stdout)

    # If the test has failed, dump its output to stderr as well. These are
    # buffered and replayed at the end of all unittests so that errors have
    # better visibility.
    if popen.returncode != 0:
      # We output the test name so we can easily find out to which unittest
      # the error message belongs.
      self._WriteStderr('Error: Test "%s" failed in configuration "%s".\n' % (
          self._name, configuration))

      # If the unittest executable itself failed, replay its output.
      if popen.origreturncode != 0:
        self._WriteStderr(stdout)

      # If there are orphaned files, dump a warning. We output to both stdout
      # and stderr so that it is seen at the time it happens, and again at
      # the end of running all tests.
      if popen.orphaned_files:
        msg = 'Error: Found %d orphaned files/directories in ' \
              'temp directory.\n' % len(popen.orphaned_files)
        self._WriteStdout(msg)
        self._WriteStderr(msg)

    # Bail if we had any errors.
    if popen.returncode != 0:
      msg = 'Test "%s" failed in configuration "%s". Exit code %d.' % \
                (self._name, configuration, popen.returncode)
      raise TestFailure(msg)

    # If we get here, all has gone well.
    return True


def _GTestColorize(text):
  """Colorizes the given Gtest output with ANSI color codes."""
  fore = colorama.Fore
  style = colorama.Style
  def _ColorizeLine(line):
    line = re.sub('^(\[\s*(?:-+|=+|RUN|PASSED|OK)\s*\])',
                  style.BRIGHT + fore.GREEN + '\\1' + style.RESET_ALL,
                  line)
    line = re.sub('^(\[\s*FAILED\s*\])',
                  style.BRIGHT + fore.RED + '\\1' + style.RESET_ALL,
                  line)
    line = re.sub('^(\s*(?:Note:|YOU HAVE .* DISABLED TEST).*)',
                  style.BRIGHT + fore.YELLOW + '\\1' + style.RESET_ALL,
                  line)
    # This colorizes the error messages inserted for orphaned files.
    line = re.sub('(^Error: .*)',
                  style.BRIGHT + fore.RED + '\\1' + style.RESET_ALL,
                  line)
    return line

  return '\n'.join([_ColorizeLine(line) for line in text.split('\n')])


class GTest(ExecutableTest):
  """This wraps a GTest unittest, with colorized output."""
  def __init__(self, *args, **kwargs):
    # Syzygy unittests all use the sharded Chrome launcher, so by default
    # shard them across a few CPUs.
    extra_args = kwargs.get('extra_args', [])
    extra_args.append('--test-launcher-jobs=5')
    kwargs['extra_args'] = extra_args

    ExecutableTest.__init__(self, *args, **kwargs)

  def _WriteStdout(self, value):
    """Colorizes the stdout of this test."""
    return super(GTest, self)._WriteStdout(_GTestColorize(value))

  def _WriteStderr(self, value):
    """Colorizes the stderr of this test."""
    return super(GTest, self)._WriteStderr(_GTestColorize(value))


class TestSuite(Test):
  """A test suite is a collection of tests that generates a catch-all
  success file upon successful completion. It is itself an instance of a
  Test, so may be nested.
  """

  def __init__(self, build_dir, name, tests, stop_on_first_failure=False):
    Test.__init__(self, build_dir, name, False)
    # tests may be anything iterable, but we want it to be a list when
    # stored internally.
    self._tests = list(tests)
    self._stop_on_first_failure = stop_on_first_failure

  def AddTest(self, test):
    self._tests.append(test)

  def AddTests(self, tests):
    self._tests.extend(self, tests)

  def _CanRun(self, configuration):
    """Determines if any of the tests can run in the given configuration."""
    can_run = False
    for test in self._tests:
      try:
        if test._CanRun(configuration):
          can_run = True
      except:
        # Output some context before letting the exception continue.
        _LOGGER.error('Configuration "%s" of test "%s" failed.',
                      configuration, test._name)  # pylint: disable=W0212
    return can_run

  def _NeedToRun(self, configuration):
    """Determines if any of the tests in this suite need to run in the given
    configuration.
    """
    need_to_run = False
    for test in self._tests:
      try:
        if test._NeedToRun(configuration):  # pylint: disable=W0212
          need_to_run = True
      except:
        # Output some context before letting the exception continue.
        _LOGGER.error('Configuration "%s" of test "%s" failed.',
                      configuration, test._name)  # pylint: disable=W0212
        raise
    return need_to_run

  def _Touch(self, configuration):
    """Implementation of this Test object.

    Touches the provided collection of tests, generating a success file for
    each test.
    """
    for test in self._tests:
      test.Touch(configuration)

  def _Run(self, configuration):
    """Implementation of this Test object.

    Runs the provided collection of tests, generating a global success file
    upon completion of them all. Runs all tests even if any test fails. Stops
    running all tests if any of them raises an exception.
    """
    success = True
    for test in self._tests:
      if not test.Run(configuration, force=self._force):
        # Keep a cumulative log of all stderr from each test that fails.
        self._WriteStderr(test._GetStderr())  # pylint: disable=W0212
        if self._stop_on_first_failure:
          return False
        success = False

    return success
