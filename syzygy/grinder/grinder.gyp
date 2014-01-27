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
        'basic_block_util.cc',
        'basic_block_util.h',
        'cache_grind_writer.cc',
        'cache_grind_writer.h',
        'coverage_data.cc',
        'coverage_data.h',
        'find.cc',
        'find.h',
        'grinder_app.cc',
        'grinder_app.h',
        'grinder_util.cc',
        'grinder_util.h',
        'grinder.h',
        'indexed_frequency_data_serializer.cc',
        'indexed_frequency_data_serializer.h',
        'lcov_writer.cc',
        'lcov_writer.h',
        'line_info.cc',
        'line_info.h',
        'grinders/coverage_grinder.cc',
        'grinders/coverage_grinder.h',
        'grinders/indexed_frequency_data_grinder.cc',
        'grinders/indexed_frequency_data_grinder.h',
        'grinders/profile_grinder.cc',
        'grinders/profile_grinder.h',
        'grinders/sample_grinder.cc',
        'grinders/sample_grinder.h',
      ],
      'dependencies': [
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
        'cache_grind_writer_unittest.cc',
        'coverage_data_unittest.cc',
        'find_unittest.cc',
        'grinder_app_unittest.cc',
        'grinder_util_unittest.cc',
        'grinder_unittests_main.cc',
        'indexed_frequency_data_serializer_unittest.cc',
        'lcov_writer_unittest.cc',
        'line_info_unittest.cc',
        'grinders/coverage_grinder_unittest.cc',
        'grinders/profile_grinder_unittest.cc',
        'grinders/sample_grinder_unittest.cc',
      ],
      'dependencies': [
        'grinder_lib',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/sampler/sampler.gyp:sampler_unittest_utils',
        '<(src)/syzygy/test_data/test_data.gyp:basic_block_entry_traces',
        '<(src)/syzygy/test_data/test_data.gyp:coverage_traces',
        '<(src)/syzygy/test_data/test_data.gyp:profile_traces',
        '<(src)/syzygy/trace/service/service.gyp:rpc_service_lib',
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
