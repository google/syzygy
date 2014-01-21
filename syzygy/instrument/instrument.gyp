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
      'target_name': 'instrument_lib',
      'type': 'static_library',
      'sources': [
        'instrument_app.cc',
        'instrument_app.h',
        'instrumenter.h',
        'instrumenters/asan_instrumenter.cc',
        'instrumenters/asan_instrumenter.h',
        'instrumenters/branch_instrumenter.cc',
        'instrumenters/branch_instrumenter.h',
        'instrumenters/bbentry_instrumenter.cc',
        'instrumenters/bbentry_instrumenter.h',
        'instrumenters/coverage_instrumenter.cc',
        'instrumenters/coverage_instrumenter.h',
        'instrumenters/entry_call_instrumenter.cc',
        'instrumenters/entry_call_instrumenter.h',
        'instrumenters/entry_thunk_instrumenter.cc',
        'instrumenters/entry_thunk_instrumenter.h',
        'instrumenters/instrumenter_with_agent.cc',
        'instrumenters/instrumenter_with_agent.h',
        'mutators/add_indexed_data_ranges_stream.cc',
        'mutators/add_indexed_data_ranges_stream.h',
        'transforms/add_indexed_frequency_data_transform.cc',
        'transforms/add_indexed_frequency_data_transform.h',
        'transforms/asan_interceptor_filter.cc',
        'transforms/asan_interceptor_filter.h',
        'transforms/asan_intercepts.cc',
        'transforms/asan_intercepts.h',
        'transforms/asan_transform.cc',
        'transforms/asan_transform.h',
        'transforms/basic_block_entry_hook_transform.cc',
        'transforms/basic_block_entry_hook_transform.h',
        'transforms/branch_hook_transform.cc',
        'transforms/branch_hook_transform.h',
        'transforms/coverage_transform.cc',
        'transforms/coverage_transform.h',
        'transforms/entry_call_transform.cc',
        'transforms/entry_call_transform.h',
        'transforms/entry_thunk_transform.cc',
        'transforms/entry_thunk_transform.h',
        'transforms/jump_table_count_transform.cc',
        'transforms/jump_table_count_transform.h',
        'transforms/thunk_import_references_transform.cc',
        'transforms/thunk_import_references_transform.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/analysis/block_graph_analysis.gyp:'
            'block_graph_analysis_lib',
        '<(src)/syzygy/block_graph/transforms/block_graph_transforms.gyp:'
            'block_graph_transforms_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
        '<(src)/syzygy/relink/relink.gyp:relink_lib',
      ],
    },
    {
      'target_name': 'instrument',
      'type': 'executable',
      'sources': [
        'instrument_main.cc',
        'instrumenter.rc',
      ],
      'dependencies': [
        'instrument_lib',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--overwrite',
          '--mode=calltrace',
          '--input-image=$(OutDir)\\test_dll.dll',
          '--output-image=$(OutDir)\\instrumented_test_dll.dll',
        ]
      },
    },
    {
      'target_name': 'instrument_unittests',
      'type': 'executable',
      'sources': [
        'instrument_app_unittest.cc',
        'instrument_unittests_main.cc',
        'instrumenters/asan_instrumenter_unittest.cc',
        'instrumenters/bbentry_instrumenter_unittest.cc',
        'instrumenters/branch_instrumenter_unittest.cc',
        'instrumenters/coverage_instrumenter_unittest.cc',
        'instrumenters/entry_call_instrumenter_unittest.cc',
        'instrumenters/entry_thunk_instrumenter_unittest.cc',
        'instrumenters/instrumenter_with_agent_unittest.cc',
        'mutators/add_indexed_data_ranges_stream_unittest.cc',
        'transforms/add_indexed_frequency_data_transform_unittest.cc',
        'transforms/asan_interceptor_filter_unittest.cc',
        'transforms/asan_transform_unittest.cc',
        'transforms/basic_block_entry_hook_transform_unittest.cc',
        'transforms/branch_hook_transform_unittest.cc',
        'transforms/coverage_transform_unittest.cc',
        'transforms/entry_call_transform_unittest.cc',
        'transforms/entry_thunk_transform_unittest.cc',
        'transforms/jump_table_count_transform_unittest.cc',
        'transforms/thunk_import_references_transform_unittest.cc',
        'transforms/unittest_util.cc',
        'transforms/unittest_util.h',
      ],
      'dependencies': [
        'instrument_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
      ],
    },
  ],
}
