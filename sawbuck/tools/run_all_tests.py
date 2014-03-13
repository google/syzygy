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
'''This scripts builds the run_unittests project in Debug and Release.
It exits with non-zero exit status on error.
'''
#!python
from build_project import BuildProjectConfig
import os.path
import optparse
import sys



_SCRIPT_DIR = os.path.dirname(__file__)
_SAWBUCK_SOLUTION = os.path.abspath(
    os.path.join(_SCRIPT_DIR, '../sawbuck.sln'))
_TEST_PROJECT = 'run_unittests'


def GetOptionParser():
  '''Creates and returns an option parser for this script.'''
  parser = optparse.OptionParser(usage='%prog [options]')
  parser.add_option('-s', '--solution',
                    dest='solution',
                    default=_SAWBUCK_SOLUTION,
                    help='Use a specific solution file.')
  parser.add_option('-p', '--project',
                    dest='project',
                    default=_TEST_PROJECT,
                    help='Test project to build')

  return parser


def Main():
  '''Runs the unittests in Debug and Release.'''
  parser = GetOptionParser()
  (options, args) = parser.parse_args()

  if args:
    parser.error('This script takes no arguments')

  BuildProjectConfig(os.path.abspath(options.solution),
                     options.project,
                     ['Debug', 'Release'])

  return 0


if __name__ == "__main__":
  sys.exit(Main())
