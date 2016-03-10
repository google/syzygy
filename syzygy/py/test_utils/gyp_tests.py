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
"""Contains functionality for extracting unittest targets from gyp files,
building them and running them. This file may be run as a standalone script
in which case it will actually execute the unittests associated with Syzygy."""
import ast
import logging
import os
import re
import subprocess
import sys
import syzygy
import testing


class Error(testing.Error):
  """An error class used for reporting problems while parsing gyp files."""
  pass


def _SplitGypDependency(dep):
  """Split a gyp dependency line into a tuple containing the gyp file path,
  and a list of targets."""
  if not isinstance(dep, str):
    raise Error('Expect each dependency to be a str.')

  tmp = dep.split(':')
  if len(tmp) > 2:
    raise Error('Invalid dependency: %s.' % dep)
  gyp_path = tmp[0]

  # Get the list of targets from the dependency.
  targets = None
  if len(tmp) > 1:
    targets = [s.strip() for s in tmp[1].split(',')]

  return (gyp_path, targets)


class GypTests(testing.TestSuite):
  """A collection of unittests extracted from the unittests.gypi gyp include
  file associated with the a gyp project."""

  def __init__(self, gyp_path=None, name='gyp_tests'):
    """Initializes this set of tests for a given GYP project.

    If gyp_path is not explicitly provided in the constructor, it is assumed
    that it is passed in on the command-line via '-g' or '--gyp-file'.

    Args:
      gyp_path: The path to the root gyp file of the project. Expects that
          there is a unittests.gypi file in the same directory, as well as
          a .sln file with a build_unittests target. If left to default value
          (None), will attempt to parse this value from the command line via
          -g/--gyp-file.
      name: The name of this test, used to generated its 'name_success.txt'
          success file. Defaults to 'gyp_tests'.
    """
    if not gyp_path:
      parser = GypTests._GetOptParser()
      options, dummy_args = parser.parse_args()
      if not options.gyp_file:
        parser.error('You must specify a root project GYP file.')
      gyp_path = options.gyp_file

    gyp_path = os.path.abspath(gyp_path)
    if not os.path.exists(gyp_path):
      raise Error('gyp file "%s" does not exist.' % (gyp_path))

    self._project_dir = os.path.dirname(gyp_path)
    self._build_dir = syzygy.NINJA_BUILD_DIR

    testing.TestSuite.__init__(self, self._build_dir, name, [])

    # Parse the gypi file and extract the tests.
    gypi_path = os.path.join(self._project_dir, 'unittests.gypi')
    self._ExtractTestsFromGypi(gypi_path)

  @staticmethod
  def _GetOptParser():
    """We override the base class option parser so as to augment it with
    the options that we make available."""
    parser = testing.TestSuite._GetOptParser()
    parser.add_option('-g', '--gyp-file', dest='gyp_file',
                      help='The root project GYP file whose tests you want '
                           'to run.')
    return parser

  def _ExtractTestsFromGypi(self, gypi_path):
    """Parses a gypi file containing a list of unittests (defined as a
    variable named 'unittests', containing a list of dependencies). This
    extracts the targets from these dependencies, each one of them
    corresponding to a unittest."""

    # literal_eval is like eval, but limited to expressions containing only
    # built in data-types. It will not execute any logic. It can throw
    # SyntaxErrors.
    gypi = ast.literal_eval(open(gypi_path).read())
    if not isinstance(gypi, dict):
      raise Error('gypi file must contain a dict.')

    if not gypi.has_key('variables'):
      raise Error('gypi dict missing "variables" key.')

    variables = gypi['variables']
    if not isinstance(variables, dict):
      raise Error('"variables" must be a dict.')

    if not variables.has_key('unittests'):
      raise Error('"variables" dict missing "unittests" key.')

    unittests = variables['unittests']
    if not isinstance(unittests, list):
      raise Error('"unittests" must be a list.')

    # Extract unittest names from each dependency.
    tests = []
    for test in unittests:
      dummy_gyp_path, targets = _SplitGypDependency(test)
      tests.extend(targets)
    tests = sorted(tests)

    # Add each test.
    for test in tests:
      self.AddTest(testing.GTest(self._build_dir, test))


def Main():
  try:
    tests = GypTests()
    return tests.Main()
  except SystemExit:
    # optparse can cause a SystemExit exception to be raised, which we catch
    # to suppress a stack trace.
    pass
  except:
    logging.exception('GypTests.Main failed.')

  return 1


if __name__ == '__main__':
  sys.exit(Main())
