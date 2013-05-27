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

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'grinder_lib',
      'type': 'static_library',
      'sources': [
        'basic_block_entry_count_grinder.cc',
        'basic_block_entry_count_grinder.h',
        'basic_block_entry_count_serializer.cc',
        'basic_block_entry_count_serializer.h',
        'basic_block_util.cc',
        'basic_block_util.h',
        'cache_grind_writer.cc',
        'cache_grind_writer.h',
        'coverage_data.cc',
        'coverage_data.h',
        'coverage_grinder.cc',
        'coverage_grinder.h',
        'find.cc',
        'find.h',
        'grinder_app.cc',
        'grinder_app.h',
        'grinder_util.cc',
        'grinder_util.h',
        'grinder.h',
        'lcov_writer.cc',
        'lcov_writer.h',
        'line_info.cc',
        'line_info.h',
        'profile_grinder.cc',
        'profile_grinder.h',
      ],
      'dependencies': [
        '<(src)/sawbuck/common/common.gyp:common',
        '<(src)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
      ],
    },
    {
      'target_name': 'grinder_unittests',
      'type': 'executable',
      'sources': [
        'basic_block_util_unittest.cc',
        'basic_block_entry_count_grinder_unittest.cc',
        'basic_block_entry_count_serializer_unittest.cc',
        'cache_grind_writer_unittest.cc',
        'coverage_data_unittest.cc',
        'coverage_grinder_unittest.cc',
        'find_unittest.cc',
        'grinder_app_unittest.cc',
        'grinder_util_unittest.cc',
        'grinder_unittests_main.cc',
        'lcov_writer_unittest.cc',
        'line_info_unittest.cc',
        'profile_grinder_unittest.cc',
      ],
      'dependencies': [
        'grinder_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/test_data/test_data.gyp:basic_block_entry_traces',
        '<(src)/syzygy/test_data/test_data.gyp:coverage_traces',
        '<(src)/syzygy/test_data/test_data.gyp:profile_traces',
      ],
    },
    {
      'target_name': 'grinder',
      'type': 'executable',
      'sources': [
        'grinder.rc',
        'grinder_main.cc',
      ],
      'dependencies': [
        'grinder_lib',
      ],
    },
  ],
}
