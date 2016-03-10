# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Build system and testing utilities related to the Syzygy project."""

import os


# Build system constants.
SYZYGY_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..'))
SRC_DIR = os.path.abspath(os.path.join(SYZYGY_DIR, '..'))
SYZYGY_SLN = os.path.join(SYZYGY_DIR, 'syzygy.sln')
SYZYGY_TARGET = 'build_all'
NINJA_BUILD_DIR = os.path.abspath(os.path.join(SYZYGY_DIR, '..', 'out'))


def GetBuildDir():
  return NINJA_BUILD_DIR
