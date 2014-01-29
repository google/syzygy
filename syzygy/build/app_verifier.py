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

"""Wrapper for running a unittest under Application Verifier."""

import logging
import optparse
import os
import re
import subprocess
import sys
import verifier


_THIRD_PARTY = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                            '..', '..', 'third_party'))
sys.path.append(_THIRD_PARTY)
import colorama


_LOGGER = logging.getLogger(os.path.basename(__file__))

# A list of per-test Application Verifier checks to not run.
_DISABLED_CHECKS = {
  'agent_common_unittests.exe': [
    # We have a test that deliberately causes an exception which is caught and
    # handled by the code under test. However, AV propogates this exception and
    # launches a modal dialog window, which causes the test to timeout.
    'Exceptions'
  ],
}

# A list of per-test Application Verifier exceptions.
_EXCEPTIONS = {
  'basic_block_entry_unittests.exe': [
    # This leak occurs due to a leaky global variable in ScopedHandle.
    ('Error', 'Leak', 2304, '.*::BasicBlockEntryTest::UnloadDll'),
    # This leak occurs due to a leaky global lock in ScopedHandle.
    ('Error', 'Locks', 513, '.*::BasicBlockEntryTest::UnloadDll'),
    # This is a known (semi-intentional) leak of the TLS index and the last
    # active thread's TLS data on module unload.
    ('Error', 'TLS', 848, '.*::BasicBlockEntryTest::UnloadDll'),
  ],
  'coverage_unittests.exe': [
    # This leak occurs due to a leaky global variable in ScopedHandle.
    ('Error', 'Leak', 2304, '.*::CoverageClientTest::UnloadDll'),
    # This leak occurs only in Debug, which leaks a thread local variable
    # used to check thread restrictions.
    ('Error', 'TLS', 848, '.*::CoverageClientTest::UnloadDll'),
  ],
  'instrument_unittests.exe': [
    # The ASAN runtime ends up freeing a heap while holding it's critical
    # section.
    ('Error', 'Locks', 513, '.*::PELibUnitTest::CheckTestDll'),
    # This leak occurs due to a leaky global lock in ScopedHandle.
    ('Error', 'Locks', 514, '.*::PELibUnitTest::CheckTestDll'),
    # This leak occurs only in Debug, which leaks a thread local variable
    # used to check thread restrictions.
    ('Error', 'TLS', 848, '.*::PELibUnitTest::CheckTestDll'),
  ],
  'parse_unittests.exe': [
    # This leak occurs due to a leaky global variable in ScopedHandle.
    ('Error', 'Leak', 2304, '.*::ParseEngineRpcTest::UnloadCallTraceDll'),
    # This leak occurs only in Debug, which leaks a thread local variable
    # used to check thread restrictions.
    ('Error', 'TLS', 848, '.*::ParseEngineRpcTest::UnloadCallTraceDll'),
  ],
  'profile_unittests.exe': [
    # This leak occurs due to a leaky global variable in ScopedHandle.
    ('Error', 'Leak', 2304, '.*::ProfilerTest::UnloadDll'),
    # This leak occurs due to a leaky global lock in ScopedHandle.
    ('Error', 'Locks', 513, 'agent::profiler::.*::ProfilerTest::UnloadDll'),
    # This leak occurs only in Debug, which leaks a thread local variable
    # used to check thread restrictions.
    ('Error', 'TLS', 848, 'agent::profiler::.*::ProfilerTest::UnloadDll'),
  ],
}


# A list of unittests that should not be run under the application verifier at
# all.
_BLACK_LIST = [
  # These can't be run under AppVerifier because we end up double hooking the
  # operating system heap function, leading to nonsense.
  'integration_tests.exe',
  'syzyasan_rtl_unittests.exe',
]


class Error(Exception):
  """Base class used for exceptions thrown in this module."""
  pass


def Colorize(text):
  """Colorizes the given app verifier output with ANSI color codes."""
  fore = colorama.Fore
  style = colorama.Style
  def _ColorizeLine(line):
    line = re.sub('^(Error.*:)(.*)',
                  style.BRIGHT + fore.RED + '\\1' + fore.YELLOW + '\\2' +
                      style.RESET_ALL,
                  line)
    line = re.sub('^(Warning:)(.*)',
                  style.BRIGHT + fore.YELLOW + '\\1' + style.RESET_ALL + '\\2',
                  line)
    return line

  return '\n'.join([_ColorizeLine(line) for line in text.split('\n')])


def FilterExceptions(image_name, errors):
  """Filter out the Application Verifier errors that have exceptions."""
  exceptions = _EXCEPTIONS.get(image_name, [])

  def _HasNoException(error):
    # Iterate over all the exceptions.
    for (severity, layer, stopcode, regexp) in exceptions:
      # And see if they match, first by type.
      if (error.severity == severity and
          error.layer == layer and
          error.stopcode == stopcode):
        # And then by regexpr match to the trace symbols.
        for trace in error.trace:
          if trace.symbol and re.match(regexp, trace.symbol):
            return False

    return True

  filtered_errors = filter(_HasNoException, errors)
  error_count = len(filtered_errors)
  filtered_count = len(errors) - error_count

  if error_count:
    suffix = '' if error_count == 1 else 's'
    filtered_errors.append(
        'Error: Encountered %d AppVerifier exception%s for %s.' %
            (error_count, suffix, image_name))

  if filtered_count:
    suffix1 = '' if filtered_count == 1 else 's'
    suffix2 = '' if len(exceptions) == 1 else 's'
    filtered_errors.append(
        'Warning: Filtered %d AppVerifier exception%s for %s using %d rule%s.' %
            (filtered_count, suffix1, image_name, len(exceptions), suffix2))

  return (error_count, filtered_errors)


def _RunUnderAppVerifier(command):
  runner = verifier.AppverifierTestRunner(False)
  image_path = os.path.abspath(command[0])
  image_name = os.path.basename(image_path)
  disabled_checks = _DISABLED_CHECKS.get(image_name, [])

  if not os.path.isfile(image_path):
    raise Error('Path not found: %s' % image_path)

  # Set up the verifier configuration.
  runner.SetImageDefaults(image_name, disabled_checks=disabled_checks)
  runner.ClearImageLogs(image_name)

  # Run the executable. We disable exception catching as it interferes with
  # Application Verifier.
  command = [image_path] + command[1:] + ['--gtest_catch_exceptions=0']
  _LOGGER.info('Running %s.', command)
  popen = subprocess.Popen(command)
  (dummy_stdout, dummy_stderr) = popen.communicate()

  # Process the AppVerifier logs, filtering exceptions.
  app_verifier_errors = runner.ProcessLogs(image_name)
  (error_count, app_verifier_errors) = FilterExceptions(
      image_name, app_verifier_errors)

  # Generate warnings for error categories that were disabled.
  for check in disabled_checks:
    app_verifier_errors.append(
          'Warning: Disabled AppVerifier %s checks.' % check)

  # Output all warnings and errors.
  for error in app_verifier_errors:
    msg = Colorize(str(error) + '\n')
    sys.stderr.write(msg)

  # Clear the verifier settings for the image.
  runner.ClearImageLogs(image_name)
  runner.ResetImage(image_name)

  if popen.returncode:
    _LOGGER.error('%s failed with return code %d.', image_name,
                 popen.returncode)

  if error_count:
    suffix = '' if error_count == 1 else 's'
    _LOGGER.error('%s failed AppVerifier test with %d exception%s.',
                  image_name, error_count, suffix)


  if popen.returncode:
    return popen.returncode

  return error_count


def _RunNormally(command):
  # We reset the image settings so that AppVerifier isn't left incidentally
  # configured.
  runner = verifier.AppverifierTestRunner(False)
  image_path = os.path.abspath(command[0])
  image_name = os.path.basename(image_path)
  runner.ClearImageLogs(image_name)
  runner.ResetImage(image_name)

  image_path = os.path.abspath(command[0])
  command = [image_path] + command[1:]
  _LOGGER.info('Running %s outside of AppVerifier.' % command)
  popen = subprocess.Popen(command)
  (dummy_stdout, dummy_stderr) = popen.communicate()

  # To be consistent with _RunUnderAppVerifier we output warnings at the end.
  sys.stderr.write(Colorize(
      'Warning: AppVerifier was disabled for this test.\n'))
  return popen.returncode


_USAGE = '%prog [options] APPLICATION -- [application options]'


def _IsBlacklisted(command):
  image_base = os.path.basename(command[0])
  if image_base in _BLACK_LIST:
    _LOGGER.info('Executable is blacklisted: %s.' % image_base)
    return True
  return False


def _ParseArgs():
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('-v', '--verbose', dest='verbose',
                    action='store_true', default=False,
                    help='Enable verbose logging.')
  parser.add_option('--on-waterfall', dest='on_waterfall',
                    action='store_true', default=False,
                    help='Indicate that we are running on the waterfall.')
  (opts, args) = parser.parse_args()

  if not len(args):
    parser.error('You must specify an application.')

  if opts.verbose:
    logging.basicConfig(level=logging.INFO)
  else:
    logging.basicConfig(level=logging.ERROR)

  return (opts, args)


def Main():
  colorama.init()
  (opts, args) = _ParseArgs()

  if _IsBlacklisted(args):
    return_code = _RunNormally(args)
  else:
    return_code = _RunUnderAppVerifier(args)
    if return_code and opts.on_waterfall:
      command = [args[0]] + ['--'] + args[1:]
      command = 'python build\\app_verifier.py %s' % ' '.join(command)
      sys.stderr.write('To reproduce this error locally run the following '
                       'command from the Syzygy root directory:\n')
      sys.stderr.write(command + '\n')

  sys.exit(return_code)


if __name__ == '__main__':
  Main()
