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
#
# Additional presubmit script. This will be run for changes to files in this
# subdirectory, as well as the root syzygy/PRESUBMIT.py.
#
# This script will be read as a string and intepreted, so __file__ is not
# available. However, it is guaranteed to be run with this file's directory as
# the current working directory.


import sys


def CheckChange(input_api, output_api, dummy_committing):
  # Make sure that etw is in our path.
  sys.path.append('../../../third_party/sawbuck/py/etw')

  # We only check Python files in this tree. The others are checked by the
  # PRESUBMIT in the root Syzygy directory.
  white_list = [r'^.*\.py$']
  black_list = []
  disabled_warnings = []
  results = input_api.canned_checks.RunPylint(
      input_api,
      output_api,
      white_list=white_list,
      black_list=black_list,
      disabled_warnings=disabled_warnings)

  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
