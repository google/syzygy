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
#
"""Contains functionality for integrating unit-tests with gcl presubmit
checks."""
import os
import sys


def MakeResult(output_api, message, committing, modified_files=None):
  """Makes a gcl result. Makes a PresubmitError result if
  |committing| is True, otherwise makes a PresubmitNotifyResult."""
  if not modified_files:
    modified_files = []
  if committing:
    return output_api.PresubmitError(message, modified_files)
  else:
    return output_api.PresubmitNotifyResult(message, modified_files)


def GetTestSuccessPath(build_path, configuration, testname):
  """Returns the path to the success file for the given test and
  configuration. |build_path| is the path to the "build" directory."""

  return os.path.abspath(os.path.join(build_path,
                                      configuration,
                                      '%s_success.txt' % testname))


def GetModifiedFiles(input_api, since=0):
  """Returns a list of files that have been modified since |since|.
  If |since| is a file, uses its modification time."""
  if isinstance(since, basestring):
    try:
      since = os.stat(since).st_mtime
    # We don't specify the exception type here as it varies depending on the
    # OS.
    except:  # pylint: disable=W0702
      since = 0

  modified_files = []
  for f in input_api.AffectedFiles(include_deletes = False):
    file_time = os.stat(f.AbsoluteLocalPath()).st_mtime
    if file_time > since:
      modified_files.append(f.LocalPath())
  return modified_files


def CheckTestSuccess(input_api, output_api, committing, configuration,
                     test_name, message=None):
  """Returns a list of files that have changed since the last time the
  given test was run. If the test needs to be re-run and |message| is a
  str, will also output the provided message."""
  # By convention, a test called NAME will generate NAME_success.txt in the
  # appropriate output directory.
  test_utils_path = os.path.join(input_api.PresubmitLocalPath(), 'py',
                                 'test_utils')
  sys.path.append(test_utils_path)
  import syzygy
  build_path = syzygy.GetBuildDir()
  success_path = GetTestSuccessPath(build_path,
                                    configuration,
                                    test_name)
  modified_files = GetModifiedFiles(input_api, success_path)
  if len(modified_files) == 0:
    return []

  results = []

  if message:
    results.append(MakeResult(output_api, message, committing))

  results.append(MakeResult(output_api,
      'These files have been modified since %s %s test ran last' %
          (configuration, test_name),
      committing,
      modified_files=modified_files))

  return results
