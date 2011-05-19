#!python
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
'''This scripts builds the given VisualStudio project in the given
configurations. It exits with non-zero exit status on error. It may also be
included as a module, defining the function BuildProjectConfig.
'''
import logging
import optparse
import os.path
import pywintypes
import sys
import win32com.client

def BuildProjectConfig(solution, projects, configs, focus=True):
  '''Builds the given projects in the given configurations.

  Args:
    solution: a Visual Studio solution file.
    projects: the paths of projects to build, relative to the solution
        directory. Multiple projects may be specified with a list.
    configs: the name of the configuration to build, ie. "Release".
        Multiple configurations may be specified with a list.
    focus: indicates if the build environment should be brought into focus
        during the build (default=True).

  Returns: the number of errors during the build. Aborts at the first
      error.
  '''
  if isinstance(projects, basestring):
    projects = [projects]

  if isinstance(configs, basestring):
    configs = [configs]

  solution = win32com.client.GetObject(os.path.abspath(solution))
  builder = solution.SolutionBuild

  if focus:
    # Force the Visual Studio window to show and give it focus.
    try:
      dte = solution.DTE
      dte.MainWindow.Visible = True
      dte.MainWindow.Activate()
    except pywintypes.com_error:
      logging.exception('Forcing focus failed.')
      pass

    try:
      # If the output window is already open, we can force it to be visible.
      # Can't quite figure out how to open it if it doesn't already exist.
      output = dte.Windows.Item('Output')
      output.Activate()
    except pywintypes.com_error:
      # We explicitly pass on this error as we expect it to happen whenever
      # the output window is not already open.
      pass

  # Build the given project in each of the desired configurations.
  errors = 0
  for project in projects:
    abs_project = os.path.abspath(project)
    for config in configs:
      print('Building project "%s" in "%s" configuration.' % (project, config))
      builder.BuildProject(config, abs_project, True)
      errors = builder.LastBuildInfo
      if errors > 0:
        break
    if errors > 0:
      break

  return errors


def GetOptionParser():
  '''Creates and returns an option parser for this script.'''
  USAGE = '%prog -s SOLUTION -p PROJECT -c CONFIG [options]'
  parser = optparse.OptionParser(usage=USAGE)
  parser.add_option('-s', '--solution',
                    dest='solution', action='store',
                    default=None,
                    help='Use a specific solution file.')
  parser.add_option('-p', '--project',
                    dest='project', action='append',
                    default=[],
                    help='Test project to build. May be specified multiple '
                         'times.')
  parser.add_option('-c', '--config',
                    dest='config', action='append',
                    default=[],
                    help='Configuration to use. May be specified multiple '
                         'times.')
  return parser


def Main():
  parser = GetOptionParser()
  (options, args) = parser.parse_args()

  if args:
    parser.error('This script takes no arguments')

  if not all((options.solution, options.project, options.config)):
    parser.error('Must specify solution, project and configuration.')

  return BuildProjectConfig(options.solution, options.project, options.config)


if __name__ == "__main__":
  sys.exit(Main())
