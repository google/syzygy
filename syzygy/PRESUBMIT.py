#!python
# Copyright 2011 Google Inc.
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
# Presubmit script for Syzygy.
import os

_UNITTEST_MESSAGE = '''\
Your %s unittests must succeed before submitting.
To clear this presubmit error, build the syzygy/run_unittests target
in the solution file syzygy/syzygy.sln, or run syzygy/run_all_tests.bat
'''

_LICENSE_HEADER = '''\
(#!python\n\
)?.*? Copyright 20.. Google Inc\.\n\
.*?\n\
.*? Licensed under the Apache License, Version 2\.0 \(the "License"\);\n\
.*? you may not use this file except in compliance with the License\.\n\
.*? You may obtain a copy of the License at\n\
.*?\n\
.*?     http://www\.apache\.org/licenses/LICENSE-2\.0\n\
.*?
.*? Unless required by applicable law or agreed to in writing, software\n\
.*? distributed under the License is distributed on an "AS IS" BASIS,\n\
.*? WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied\.\n\
.*? See the License for the specific language governing permissions and\n\
.*? limitations under the License\.\n\
'''

def CheckUnittestsRan(input_api, output_api, committing, configuration):
  '''Checks that the unittests success file is newer than any modified file'''
  success_path = "%s/unittest_success.txt" % configuration
  def MakeResult(message, modified_files=[]):
    if committing:
      return output_api.PresubmitError(message, modified_files)
    else:
      return output_api.PresubmitNotifyResult(message, modified_files)
  os_path = input_api.os_path
  success_path = os_path.join(input_api.PresubmitLocalPath(),
                              success_path)

  if not os_path.exists(success_path):
    return [MakeResult(_UNITTEST_MESSAGE % configuration)]

  success_time = os.stat(success_path).st_mtime
  modified_files = []
  for f in input_api.AffectedFiles(include_deletes = False):
    file_time = os.stat(f.AbsoluteLocalPath()).st_mtime
    if file_time > success_time:
      modified_files.append(f.LocalPath())

  result = []
  if modified_files:
    result.append(MakeResult('These files have been modified since %s '
                             'unittests ran last' % configuration,
                             modified_files))

  return result


def CheckChange(input_api, output_api, committing):
  # The list of (canned) checks we perform on all changes.
  checks = [
    input_api.canned_checks.CheckChangeHasDescription,
    input_api.canned_checks.CheckChangeLintsClean,
    input_api.canned_checks.CheckChangeHasNoCrAndHasOnlyOneEol,
    input_api.canned_checks.CheckChangeHasNoTabs,
    input_api.canned_checks.CheckChangeHasNoStrayWhitespace,
    input_api.canned_checks.CheckLongLines,
    input_api.canned_checks.CheckChangeSvnEolStyle,
    input_api.canned_checks.CheckDoNotSubmit,
  ]

  results = []
  for check in checks:
    results += check(input_api, output_api)

  results += input_api.canned_checks.CheckLicense(input_api,
                                                  output_api,
                                                  _LICENSE_HEADER)

  results += CheckUnittestsRan(input_api, output_api, committing, "Debug")
  results += CheckUnittestsRan(input_api, output_api, committing, "Release")

  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
