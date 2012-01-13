# Copyright 2011 Google Inc.
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
      'target_name': 'reorder_lib',
      'type': 'static_library',
      'sources': [
        'comdat_order.cc',
        'comdat_order.h',
        'dead_code_finder.cc',
        'dead_code_finder.h',
        'linear_order_generator.cc',
        'linear_order_generator.h',
        'random_order_generator.cc',
        'random_order_generator.h',
        'reorderer.cc',
        'reorderer.h',
      ],
      'dependencies': [
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
      ],
    },
    {
      'target_name': 'reorder',
      'type': 'executable',
      'sources': [
        'reorder_main.cc',
        'reorderer.rc',
      ],
      'dependencies': [
        'reorder_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--input-dll=..\\reorder\\test_data\\test_dll.dll',
          '--instrumented-dll=$(OutDir)\\instrumented_test_dll.dll',
          '--output-file=$(OutDir)\\test_dll_order.json',
          '--output-comdats=$(OutDir)\\test_dll_comdats.txt',
          '--output-stats',
          '--pretty-print',
          '..\\reorder\\test_data\\call_trace.etl',
          '..\\reorder\\test_data\\kernel.etl',
        ]
      },
    },
    {
      'target_name': 'reorder_unittests',
      'type': 'executable',
      'sources': [
        'dead_code_finder_unittest.cc',
        'linear_order_generator_unittest.cc',
        'order_generator_test.cc',
        'order_generator_test.h',
        'random_order_generator_unittest.cc',
        'reorder_unittests_main.cc',
        'reorderer_unittest.cc',
        '../pe/unittest_util.cc',
        '../pe/unittest_util.h',
      ],
      'dependencies': [
        'reorder_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '../core/core.gyp:core_unittest_utils',
        '../pe/pe.gyp:pe_unittest_utils',
        '../test_data/test_data.gyp:test_dll',
        '../test_data/test_data.gyp:instrumented_test_dll',
      ],
    }
  ],
}
