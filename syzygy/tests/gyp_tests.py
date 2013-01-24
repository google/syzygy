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
"""Creates a GypTests object that encapsulates all unittests defined in
unittests.gypi."""

import os.path
import sys


_SYZYGY_DIR = os.path.abspath(os.path.dirname(__file__) + '/..')
_SYZYGY_GYP = os.path.join(_SYZYGY_DIR, 'syzygy.gyp')
_SCRIPT_DIR = os.path.join(_SYZYGY_DIR, 'py')


if _SCRIPT_DIR not in sys.path:
  sys.path.insert(0, _SCRIPT_DIR)
import test_utils.gyp_tests as gyp_tests  # pylint: disable=F0401


def MakeTest():
  return gyp_tests.GypTests(gyp_path=_SYZYGY_GYP)


if __name__ == '__main__':
  sys.exit(MakeTest().Main())
