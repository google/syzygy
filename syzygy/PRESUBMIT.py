#!python
# Copyright 2012 Google Inc.
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

import datetime
import os
import sys


# Determine the root of the source tree. We use getcwd() instead of __file__
# because gcl loads this script as text and runs it using eval(). In this
# context the variable __file__ is undefined. However, gcl assures us that
# the current working directory will be the directory containing this file.
SYZYGY_ROOT_DIR = os.path.abspath(os.getcwd())


# Bring in some presubmit tools.
sys.path.insert(0, os.path.join(SYZYGY_ROOT_DIR, 'py'))
import test_utils.presubmit as presubmit


# Bring in internal-only presubmit checks. These live in a parallel
# repository that is overlaid with the public version of syzygy. The
# internal presubmit check is expected to live in the 'internal'
# subdirectory off the syzygy root.
try:
  internal_dir = os.path.join(SYZYGY_ROOT_DIR, 'internal')
  if os.path.isdir(internal_dir):
    sys.path.insert(0, internal_dir)
  import internal_presubmit
except ImportError:
  internal_presubmit = None


_UNITTEST_MESSAGE = """\
Your %%s unittests must succeed before submitting! To clear this error,
  run: %s""" % os.path.join(SYZYGY_ROOT_DIR, 'run_all_tests.bat')


_YEAR = datetime.datetime.now().year
_LICENSE_HEADER = """\
(#!python\n\
)?.*? Copyright %04d Google Inc\.\n\
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
""" % _YEAR

def CheckUnittestsRan(input_api, output_api, committing, configuration):
  """Checks that the unittests success file is newer than any modified file"""
  return presubmit.CheckTestSuccess(input_api, output_api, committing,
                                    configuration, 'ALL',
                                    message=_UNITTEST_MESSAGE % configuration)


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

  gyp_file_re = r'.+\.gypi?$'
  py_file_re = r'.+\.py$'
  white_list = input_api.DEFAULT_WHITE_LIST + (gyp_file_re, py_file_re)
  sources = lambda x: input_api.FilterSourceFile(x, white_list=white_list)
  results += input_api.canned_checks.CheckLicense(input_api,
                                                  output_api,
                                                  _LICENSE_HEADER,
                                                  source_file_filter=sources)

  results += CheckUnittestsRan(input_api, output_api, committing, "Debug")
  results += CheckUnittestsRan(input_api, output_api, committing, "Release")

  if internal_presubmit:
    results += internal_presubmit.CheckChange(input_api,
                                              output_api,
                                              committing)

  return results


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api, False)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api, True)
