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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'zap_timestamp_lib',
      'type': 'static_library',
      'sources': [
        'zap_timestamp.cc',
        'zap_timestamp.h',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:dia_sdk',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
      ],
    },
    {
      'target_name': 'zap_timestamp_unittests',
      'type': 'executable',
      'sources': [
        'zap_timestamp_unittest.cc',
        'zap_timestamp_unittests_main.cc',
      ],
      'dependencies': [
        'zap_timestamp_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/testing/gtest.gyp:gtest',
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
