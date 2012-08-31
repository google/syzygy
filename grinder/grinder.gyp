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

{
  'variables': {
    'chromium_code': 1,
  },
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'grinder_lib',
      'type': 'static_library',
      'sources': [
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
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:dia_sdk',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
      ],
    },
    {
      'target_name': 'grinder_unittests',
      'type': 'executable',
      'sources': [
        'grinder_app_unittest.cc',
        'grinder_util_unittest.cc',
        'grinder_unittests_main.cc',
        'lcov_writer_unittest.cc',
        'line_info_unittest.cc',
        'profile_grinder_unittest.cc',
      ],
      'dependencies': [
        'grinder_lib',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(DEPTH)/syzygy/test_data/test_data.gyp:profile_traces',
        '<(DEPTH)/syzygy/test_data/test_data.gyp:coverage_traces',
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
