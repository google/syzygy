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
"""Enumerates all tests in this directory, and runs them. Each test is
expected to be a module containing a MakeTest function that returns an instance
of testing.Test."""

import os
import re
import sys
import logging


_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_SYZYGY_DIR = os.path.abspath(_SELF_DIR + '/..')
_SCRIPT_DIR = os.path.join(_SYZYGY_DIR, 'py')


if _SCRIPT_DIR not in sys.path:
  sys.path.insert(0, _SCRIPT_DIR)
import test_utils.syzygy as syzygy  # pylint: disable=F0401
import test_utils.testing as testing  # pylint: disable=F0401


def MakeTest():
  # All tests must run and pass consecutively. This is because the first
  # test builds the entire project, and the second test runs the unittests.
  tests = testing.TestSuite(syzygy.GetBuildDir(), 'ALL', [],
                            stop_on_first_failure=True)

  # Add the tests in alphabetical order.
  for test in sorted(os.listdir(_SELF_DIR)):
    if test == 'run_all_tests.py' or not re.search('\.py$', test):
      continue

    module_name = re.sub('\.py$', '', test)
    test_module = __import__(module_name)
    tests.AddTest(test_module.MakeTest())

  return tests


if __name__ == "__main__":
  sys.exit(MakeTest().Main())
