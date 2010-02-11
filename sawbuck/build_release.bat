@echo off
rem = """
:: Copyright 2009 Google Inc.
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::     http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.
:: Make sure the tools directory is in our python path.
set PYTHONPATH=%~p0tools
"%~p0..\third_party\python_24\python.exe" -x "%~f0" %*
goto endofPython """
'''This scripts builds the current version in debug and release, then
copies the produced installers to sawbuck-<version>-{debug|release}.msi
for easy archiving.
'''
#!python
import os.path
import shutil
import sys
import win32com.client
from template_replace import ReadKeyFile


_SCRIPT_DIR = os.path.dirname(__file__)
_SAWBUCK_SOLUTION = os.path.join(_SCRIPT_DIR, 'sawbuck.sln')
_INSTALLER_PROJECT = os.path.join(_SCRIPT_DIR, 'installer/sawbuck.vcproj')
_VERSION_FILE = os.path.join(_SCRIPT_DIR, 'VERSION')


def BuildProjectConfig(builder, config, project):
  '''Builds a given project in a given configuration, exits on error.
  
  Args:
    builder: a Visual Studio SolutionBuild object.
    config: the name of the configuration to build, f.ex. "Release".
    project: the path of a solution to build, relative to the builder's
        solution directory.
  ''' 
  print 'Building project "%s" in "%s" configuration' % (project, config)
  project = os.path.normpath(project)
  builder.BuildProject(config, project, True)
  errors = builder.LastBuildInfo
  
  if errors != 0:
    print '%d errors while building config %s.' % (errors, config)
    sys.exit(errors)


def Main():
  '''Builds the sawbuck installer in Debug and Release, and copies
  the resultant installers to the Sawbuck solution directory.
  '''
  v = {}
  ReadKeyFile(_VERSION_FILE, v)
  version = map(int, (v['MAJOR'], v['MINOR'], v['BUILD'], v['PATCH']))
  print "Building version %d.%d.%d.%d" % tuple(version)

  solution = win32com.client.GetObject(_SAWBUCK_SOLUTION)
  builder = solution.SolutionBuild

  BuildProjectConfig(builder, 'Debug', _INSTALLER_PROJECT)
  BuildProjectConfig(builder, 'Release', _INSTALLER_PROJECT)
  
  basename = 'sawbuck-%d.%d.%d.%d' % tuple(version)
  shutil.copyfile(os.path.join(_SCRIPT_DIR, 'Debug/sawbuck.msi'),
                  os.path.join(_SCRIPT_DIR, '%s-debug.msi' % basename))
  shutil.copyfile(os.path.join(_SCRIPT_DIR, 'Release/sawbuck.msi'),
                  os.path.join(_SCRIPT_DIR, '%s-release.msi' % basename))


if __name__ == "__main__":
  sys.exit(Main())

rem = """
:endofPython """
