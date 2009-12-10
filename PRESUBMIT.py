#!python
# Copyright 2009 Google Inc.
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
# Presubmit script for Sawbuck.

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

  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
