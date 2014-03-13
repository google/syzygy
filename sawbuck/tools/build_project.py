#!python
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

"""This scripts builds VisualStudio projects.

Given the path to a solution file and one or more project and configuration
names, this script will open the solution file and build each project in
each configuration.

It exits with non-zero exit status on error. It may also be included as a
module, defining the function BuildProjectConfig, which exposes the
functionality described above.
"""

import itertools
import logging
import optparse
import os.path
import pywintypes
import sys
import time
import win32com.client


_FOLDER_GUID = '{66A26720-8FB5-11D2-AA7E-00C04F688DDE}'
_SUBPROJECT_GUID = '{66A26722-8FB5-11D2-AA7E-00C04F688DDE}'
_PROJECT_GUID = '{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}'


_LOGGER = logging.getLogger(os.path.basename(__file__))


class Error(Exception):
  """An error class used for reporting build failures."""
  pass


def _ToList(string_or_list):
  if isinstance(string_or_list, basestring):
    string_or_list = [string_or_list]
  return string_or_list


def _ItemIter(items):
  for i in xrange(1, items.Count + 1):
    yield items.Item(i)


class Solution(object):
  """This class encapsulates a Visual Studio Solution."""
  def __init__(self, path=None):
    self._projects = {}
    self._solution = None
    self._indent = 0
    if path:
      self.OpenSolution(path)

  def OpenSolution(self, path):
    """Open the solution file given by path.

    This implicitly closes any solution that might previously have been
    open for this item. It does not close the UI if it had previously
    been shown. If there is an existing UI open for the solution, that
    UI instanc is co-opted for this Solution instance.

    Args:
      path: The path to a solution file. The file must end with the .sln
          extension and must exist.

    Returns: None on success. Raised on error.
    """
    try:
      if os.path.splitext(path)[1].lower() != '.sln':
        raise Error('File is not a Visual Studio solution: %s' % path)
      if not os.path.isfile(path):
        raise Error('File not found: %s' % path)
      path = os.path.abspath(path)
      self._solution = self._OpenSolutionFile(path)
      self._projects = self._LoadProjects()
    except:
      self._solution = None
      self._projects = {}
      raise

  def __getitem__(self, project_name):
    return self._projects[project_name]

  def __iter__(self):
    return self._projects.__iter__()

  def Show(self, window_name=None):
    """Shows the Visual Studio IDE, optionally bringing the window
    called window_name to the fore-front.

    Args:
      window_name: The (optional) name of the window to bring focus to.

    Returns: None on success. Raises an Error on failure.
    """
    try:
      window_name_lower = window_name.lower()
      dte = self._solution.DTE
      dte.MainWindow.Visible = True
      dte.UserControl = True
      if window_name:
        for window in _ItemIter(self._solution.DTE.Windows):
          if window.Caption.lower() == window_name_lower:
            if window.Activate:
              window.Activate()
            break
    except pywintypes.com_error:  # pylint: disable=E1101
      _LOGGER.exception('Failed to show window: %s', window_name)

  def BuildProject(self, project_name, config):
    """Builds the given project in the given configuration.

    Args:
      project_name: The name of projects to build.
      config: The name of the configuration to build, ie. "Release".

    Returns: None on success. Raises an Error on failure.
    """
    num_errors = 0
    try:
      _LOGGER.info('Building %s in %s configuration', project_name, config)
      project = self._projects[project_name]
      builder = self._solution.SolutionBuild
      saved_config = self._GetActiveConfiguration(project)
      try:
        builder.SolutionConfigurations(config).Activate()
        builder.BuildProject(config, project.FullName, True)
        num_errors = builder.LastBuildInfo
      finally:
        builder.SolutionConfigurations(saved_config).Activate()
    except pywintypes.com_error:  # pylint: disable=E1101
      _LOGGER.error('Failed to build "%s" in %s configuration.',
                    project, config)
      # Reraise the error with a new type.
      raise Error, sys.exc_info()[1], sys.exc_info()[2]

    if num_errors != 0:
      raise Error(
          'config "%s" of "%s" failed to build with %d error%s.' % (
              config,
              project_name,
              num_errors,
              '' if num_errors == 1 else 's'))

  def _OpenSolutionFile(self, path):
    _LOGGER.debug('Opening solution file: %s', path)
    for _ in xrange(3):
      try:
        return win32com.client.GetObject(path)
      except pywintypes.com_error:  # pylint: disable=E1101
        time.sleep(2)
        pass
    raise Error('Failed to initialize COM automation of %s.' % path)

  def _LoadProjects(self):
    _LOGGER.debug('Loading projects...')
    output = {}
    try:
      self._LoadProjectsFromItems(self._solution.Projects, 0, output)
      return output
    except pywintypes.com_error:  # pylint: disable=E1101
      # Reraise the error with a new type.
      raise Error, sys.exc_info()[1], sys.exc_info()[2]

  def _LoadProjectsFromItems(self, items, indent, output):
    for item in _ItemIter(items):
      self._LoadProjectsFromItem(item, indent, output)

  _TEMPLATE = 'Loading: %s- %s %s'

  def _LoadProjectsFromItem(self, item, indent, output):
    _LOGGER.debug(self._TEMPLATE, ' ' * indent, item.Name, item.Kind)
    indent += 2
    if item.Kind == _PROJECT_GUID:
      output[item.Name] = item
    elif item.Kind == _SUBPROJECT_GUID:
      if item.SubProject is None:
        _LOGGER.debug(self._TEMPLATE, ' ' * indent, item.Name, 'Not Loaded')
      else:
        self._LoadProjectsFromItem(item.SubProject, indent, output)
    elif item.Kind == _FOLDER_GUID:
      self._LoadProjectsFromItems(item.ProjectItems, indent, output)

  @staticmethod
  def _GetActiveConfiguration(project):
    # For some reason, stringing these property accesses into a single
    # expression does not work. They need to be on separate lines.
    cm = project.ConfigurationManager
    ac = cm.ActiveConfiguration
    return ac.ConfigurationName


def BuildProjectConfig(solution_path, project_names, configs, show_ui=True):
  """Builds the given projects in the given configurations.

  Args:
    solution_path: A Visual Studio solution file.
    project_names: The name(s) of projects to build. This parameter accepts
        either a single string or a list/tuple of strings.
    configs: The name(s) of the configuration to build, ie. "Release".
        This parameter accepts either a single string or a list/tuple of
        strings.
    show_ui: indicates if the build environment's UI should be shown during
        the build. If true, a best-effort attemtp to bring the UI into
        focus will also be made.

  Returns: None on success. Raises an Error on failure.
  """
  project_names = _ToList(project_names)
  configs = _ToList(configs)
  solution = Solution(solution_path)
  if show_ui:
    solution.Show('Output')
  for project_name, config in itertools.product(project_names, configs):
    solution.BuildProject(project_name, config)


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
    _LOGGER.exception('Build failed.')
    return 1

  return 0


if __name__ == "__main__":
  sys.exit(Main())
