# Copyright 2013 Google Inc. All Rights Reserved.
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

{
  'targets': [
    {
      'target_name': 'jump_table_count_client',
      'type': 'shared_library',
      'sources': [
        'jump_table_count.cc',
        'jump_table_count.def',
        'jump_table_count.h',
        'jump_table_count.rc',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'jump_table_count_unittests',
      'type': 'executable',
      'sources': [
        'jump_table_count_unittest.cc',
        'jump_table_count_unittests_main.cc',
      ],
      'dependencies': [
        'jump_table_count_client',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
       ],
    },
  ],
}
