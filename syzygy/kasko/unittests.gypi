# Copyright 2015 Google Inc. All Rights Reserved.
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

# Unittests should be added to this file so that they are discovered by
# the unittest infrastructure. Each unit-test should be a target of a
# dependency, and should correspond to an executable that will be created
# in the output directory. For example:
#
#   '<(src)/syzygy/kasko/kasko.gyp:kasko_unittests',
#
# The target of this dependency rule is 'kasko_unittests', and it
# corresponds to the executable '<build_dir>/Debug/kasko_unittests.exe'.
# (Or 'Release' instead of 'Debug', as the case may be.)

{
  'variables': {
    'unittests': [

      # Assembler unittests.
      '<(src)/syzygy/assm/assm.gyp:assm_unittests',

      # Common tests.
      '<(src)/syzygy/common/common.gyp:common_unittests',

      # RPC Common tests.
      '<(src)/syzygy/common/rpc/rpc.gyp:common_rpc_unittests',

      # Core tests.
      '<(src)/syzygy/core/core.gyp:core_unittests',

      # Kasko tests.
      '<(src)/syzygy/kasko/kasko.gyp:kasko_unittests',

      # Kasko API tests.
      '<(src)/syzygy/kasko/kasko.gyp:kasko_api_tests',
    ],
  }
}
