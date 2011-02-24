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
import os.path
import optparse
import sys
import win32com.client


_SCRIPT_DIR = os.path.dirname(__file__)
_SAWBUCK_SOLUTION = os.path.abspath(
    os.path.join(_SCRIPT_DIR, '../sawbuck.sln'))
_TEST_PROJECT = os.path.abspath(
    os.path.join(_SCRIPT_DIR, '../run_unittests.vcproj'))


def BuildProjectConfig(builder, config, project):
  '''Builds a given project in a given configuration.

  Args:
    builder: a Visual Studio SolutionBuild object.
    config: the name of the configuration to build, f.ex. "Release".
    project: the path of a solution to build, relative to the builder's
        solution directory.

  Returns: the number of errors during the build.
  '''
  print 'Building project "%s" in "%s" configuration' % (project, config)
  builder.BuildProject(config, project, True)

  return builder.LastBuildInfo


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

  solution = win32com.client.GetObject(os.path.abspath(options.solution))
  builder = solution.SolutionBuild

  # Force the output window to show and give it focus.
  autohides = None
  try:
    dte = solution.DTE
    dte.MainWindow.Visible = True
    output = dte.Windows['Output']
    autohides = output.AutoHides
    output.AutoHides = False
    output.SetFocus()
  except:
    pass

  project = os.path.abspath(options.project)
  errors = BuildProjectConfig(builder, 'Debug', project)
  if errors == 0:
    errors = BuildProjectConfig(builder, 'Release', project)

  # Restore the output window autohide status.
  if autohides != None:
    try:
      output.AutoHides = autohides
    except:
      pass

  return errors


if __name__ == "__main__":
  sys.exit(Main())
