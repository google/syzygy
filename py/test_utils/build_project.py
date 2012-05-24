#!python
# Copyright 2012 Google Inc.
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
"""This scripts builds the given VisualStudio project in the given
configurations. It exits with non-zero exit status on error. It may also be
included as a module, defining the function BuildProjectConfig.
"""
import logging
import optparse
import os.path
import pywintypes
import sys
import win32com.client

class Error(Exception):
  """An error class used for reporting build failures."""
  pass


def BuildProjectConfig(solution_path, project_paths, configs, focus=True):
  """Builds the given projects in the given configurations.

  Args:
    solution_path: a Visual Studio solution file.
    project_paths: the paths of projects to build, relative to the solution
        directory. Multiple projects may be specified with a list.
    configs: the name of the configuration to build, ie. "Release".
        Multiple configurations may be specified with a list.
    focus: indicates if the build environment should be brought into focus
        during the build (default=True).

  Returns: None on success. Raises an Error on failure.
  """
  if isinstance(project_paths, basestring):
    project_paths = [project_paths]

  if isinstance(configs, basestring):
    configs = [configs]

  solution_path = os.path.abspath(solution_path)
  solution_dir = os.path.dirname(solution_path)
  try:
    solution = win32com.client.GetObject(solution_path)
    builder = solution.SolutionBuild
  except pywintypes.com_error:  # pylint: disable=E1101
    # Reraise the error with a new type.
    raise Error, sys.exc_info()[1], sys.exc_info()[2]

  if focus:
    # Force the Visual Studio window to show and give it focus.
    try:
      dte = solution.DTE
      dte.MainWindow.Visible = True
      dte.MainWindow.Activate()
    except pywintypes.com_error:  # pylint: disable=E1101
      logging.error('Forcing focus failed.')

    try:
      # If the output window is already open, we can force it to be visible.
      # Can't quite figure out how to open it if it doesn't already exist.
      output = dte.Windows.Item('Output')
      output.Activate()
    except pywintypes.com_error:  # pylint: disable=E1101
      # We explicitly pass on this error as we expect it to happen whenever
      # the output window is not already open.
      pass

  # Build each project in each of the desired configurations.
  for project_path in project_paths:
    abs_project_path = os.path.abspath(project_path)

    # Get a short project name relative to the solution directory.
    # This makes log message easier to read.
    rel_project_path = os.path.relpath(abs_project_path, solution_dir)

    for config in configs:
      logging.info('Building configuration "%s" of project "%s".',
                   config, project_path)
      errors = 0
      try:
        builder.BuildProject(config, abs_project_path, True)
        errors = builder.LastBuildInfo
      except pywintypes.com_error:  # pylint: disable=E1101
        logging.error('Configuration "%s" of "%s" failed to build.',
            config, project_path)
        # Reraise the error with a new type.
        raise Error, sys.exc_info()[1], sys.exc_info()[2]

      if errors > 0:
        raise Error(
            'Configuration "%s" of "%s" failed to build with %d error%s.' %
                (config, rel_project_path, errors, '' if errors == 1 else 's'))


def GetOptionParser():
  """Creates and returns an option parser for this script."""
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
    parser.error('This script takes no arguments.')

  if not all((options.solution, options.project, options.config)):
    parser.error('Must specify solution, project and configuration.')

  try:
    BuildProjectConfig(options.solution, options.project, options.config)
  except Error:
    logging.exception('Build failed.')
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(Main())
