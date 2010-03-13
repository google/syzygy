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
import sys
import win32com.client


_SCRIPT_DIR = os.path.dirname(__file__)
_SAWBUCK_SOLUTION = os.path.abspath(
    os.path.join(_SCRIPT_DIR, '../sawbuck.sln'))
_TEST_PROJECT = os.path.abspath(
    os.path.join(_SCRIPT_DIR, '../run_unittests.vcproj'))


def BuildProjectConfig(builder, config, project):
  '''Builds a given project in a given configuration, exits on error.

  Args:
    builder: a Visual Studio SolutionBuild object.
    config: the name of the configuration to build, f.ex. "Release".
    project: the path of a solution to build, relative to the builder's
        solution directory.
  '''
  print 'Building project "%s" in "%s" configuration' % (project, config)
  builder.BuildProject(config, project, True)
  errors = builder.LastBuildInfo

  if errors != 0:
    print '%d errors while building config %s.' % (errors, config)
    sys.exit(errors)


def Main():
  '''Runs the unittests in Debug and Release.'''
  solution = win32com.client.GetObject(_SAWBUCK_SOLUTION)
  builder = solution.SolutionBuild

  BuildProjectConfig(builder, 'Debug', _TEST_PROJECT)
  BuildProjectConfig(builder, 'Release', _TEST_PROJECT)


if __name__ == "__main__":
  sys.exit(Main())
