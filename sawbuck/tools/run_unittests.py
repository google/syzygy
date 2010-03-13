#!python
# Copyright 2009 Google Inc.
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
'''
Application verifier wrapper script. Runs a given test or tests under
appverifier with a given set of settings, outputting any resultant errors
in an output format suitable for the Visual Studio output window.
'''
import datetime
import optparse
import os
import os.path
import subprocess
import sys
import time
import verifier


def FilterAppVerifierExceptions(exe_path, errors):
  '''Filters 'errors' for allowed (exception) App Verifier errors.

    Returns: a filtered list of 'errors'.
  '''
  module, ext = os.path.splitext(os.path.basename(exe_path))

  def ModuleInTrace(module, error):
    module = module.lower()
    for entry in error.trace:
      if entry.module.lower() == module:
        return True

    return False

  def IsNotAppVerifierException(error):
    # SAV has an App Verifier problem  where it abandons a
    # critical section on unloading. Unfortunately there's not
    # much we can specifically identify this error on, so we go
    # heuristic. Test that the module under testing does not
    # appear in the stack trace :(.
    if error.stopcode == '0x201' and error.layer == 'Locks':
      return ModuleInTrace(module, error)

    # No exception, this is an error.
    return True

  return filter(IsNotAppVerifierException, errors)


def RunOneTest(exe_path, target):
  '''Runs a single unittest executable, specified by target, in exe_path.

    Args:
      exe_path: path to the directory where the target is to be found.
      target: GYP target specification for the unittest executable,
          e.g. "../foo/bar/xyz.gyp:some_unittests".

    Returns:
      True iff the unittest returned exit code 0.
  '''
  # The executable name is everything from the colon.
  exe_name = target.split(':')[-1]
  test_path = os.path.join(exe_path, exe_name)

  if verifier.HasAppVerifier():
    test_path += '.exe'
    print "running test with appverifier ", target
    (retval, errors) = verifier.RunTestWithVerifier(test_path)

    errors = FilterAppVerifierExceptions(test_path, errors)
    if errors and len(errors):
      print "Application Verifier errors:\n\n"
      for error in errors:
        print "*** ERROR ***"
        print error

      # Return failure on app verifier errors.
      return False
  else:
    print "running test ", target
    retval = subprocess.call(test_path)

  return retval == 0


DESCRIPTION_ = '''Takes a set of GYP unittest targets and runs them.
Outputs the unittest log and failures to stdout, and generates
the success file only if all unittests succeed.
'''


def GetOptionParser():
  '''Constructs an initialized option parser for this script'''
  parser = optparse.OptionParser(description = DESCRIPTION_)
  parser.add_option('--success-file',
                    dest = 'success_file',
                    help = 'file to write when all unittests succeed')
  parser.add_option('--exe-dir',
                    dest = 'exe_dir',
                    help = 'the directory where the unittest '
                           'executables are found')
  return parser


def Main():
  '''Runs unittests and creates a file on their success.'''
  parser = GetOptionParser()
  (options, args) = parser.parse_args()
  if not options.success_file:
    parser.error('you must provide a success file')
  if not options.exe_dir:
    parser.error('you must provide an exe dir')

  succeeded = True
  for test in args:
    if not RunOneTest(options.exe_dir, test):
      succeeded = False

  if succeeded:
    f = file(options.success_file, 'w')
    f.write(str(datetime.datetime.now()))
    return 0
  else:
    return 1


VERIFIER_MESSAGE = '''\
Warning: you don't have Microsoft application verifier installed.
Please download it from Microsoft and install it to get better test coverage.
See [http://www.google.com/search?q=application+verifier+download].
'''


if __name__ == '__main__':
  if not verifier.HasAppVerifier():
    print VERIFIER_MESSAGE
  sys.exit(Main())
