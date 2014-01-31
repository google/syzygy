# Copyright 2012 Google Inc. All Rights Reserved.
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
  'targets': [
    {
      'target_name': 'reorder_lib',
      'type': 'static_library',
      'sources': [
        'basic_block_optimizer.cc',
        'basic_block_optimizer.h',
        'dead_code_finder.cc',
        'dead_code_finder.h',
        'linear_order_generator.cc',
        'linear_order_generator.h',
        'orderers/explicit_orderer.cc',
        'orderers/explicit_orderer.h',
        'random_order_generator.cc',
        'random_order_generator.h',
        'reorder_app.cc',
        'reorder_app.h',
        'reorderer.cc',
        'reorderer.h',
        'transforms/basic_block_layout_transform.cc',
        'transforms/basic_block_layout_transform.h',
      ],
      'dependencies': [
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/grinder/grinder.gyp:grinder_lib',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/playback/playback.gyp:playback_lib',
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
        '<(src)/base/base.gyp:base',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--input-image=<(src)\\syzygy\\reorder\\test_data\\test_dll.dll',
          '--instrumented-image=$(OutDir)\\instrumented_test_dll.dll',
          '--output-file=$(OutDir)\\test_dll_order.json',
          '--output-stats',
          '--pretty-print',
          '<(src)\\syzygy\\reorder\\test_data\\call_trace.etl',
          '<(src)\\syzygy\\reorder\\test_data\\kernel.etl',
        ]
      },
    },
    {
      'target_name': 'reorder_unittests',
      'type': 'executable',
      'sources': [
        'basic_block_optimizer_unittest.cc',
        'dead_code_finder_unittest.cc',
        'linear_order_generator_unittest.cc',
        'order_generator_test.cc',
        'order_generator_test.h',
        'orderers/explicit_orderer_unittest.cc',
        'random_order_generator_unittest.cc',
        'reorder_app_unittest.cc',
        'reorder_unittests_main.cc',
        'reorderer_unittest.cc',
        'transforms/basic_block_layout_transform_unittest.cc',
        '<(src)/syzygy/pe/unittest_util.cc',
        '<(src)/syzygy/pe/unittest_util.h',
      ],
      'dependencies': [
        'reorder_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/test_data/test_data.gyp:basic_block_entry_counts',
        '<(src)/syzygy/test_data/test_data.gyp:'
            'call_trace_instrumented_test_dll',
        '<(src)/syzygy/test_data/test_data.gyp:call_trace_traces',
        '<(src)/syzygy/test_data/test_data.gyp:copy_test_dll',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    }
  ],
}
