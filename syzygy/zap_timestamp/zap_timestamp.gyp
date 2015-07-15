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
      'target_name': 'zap_timestamp_lib',
      'type': 'static_library',
      'sources': [
        'zap_timestamp_app.cc',
        'zap_timestamp_app.h',
        'zap_timestamp.cc',
        'zap_timestamp.h',
      ],
      'dependencies': [
        '<(src)/syzygy/application/application.gyp:application_lib',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
      ],
    },
    {
      'target_name': 'zap_timestamp_unittests',
      'type': 'executable',
      'sources': [
        'zap_timestamp_app_unittest.cc',
        'zap_timestamp_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'zap_timestamp_lib',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'zap_timestamp',
      'type': 'executable',
      'sources': [
        'zap_timestamp.rc',
        'zap_timestamp_main.cc',
      ],
      'dependencies': [
        'zap_timestamp_lib',
      ],
    },
  ],
}
