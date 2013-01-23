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
  'targets': [
    {
      'target_name': 'pe_transforms_lib',
      'type': 'static_library',
      'sources': [
        'add_debug_directory_entry_transform.cc',
        'add_debug_directory_entry_transform.h',
        'add_imports_transform.cc',
        'add_imports_transform.h',
        'add_metadata_transform.cc',
        'add_metadata_transform.h',
        'add_pdb_info_transform.cc',
        'add_pdb_info_transform.h',
        'explode_basic_blocks_transform.cc',
        'explode_basic_blocks_transform.h',
        'prepare_headers_transform.cc',
        'prepare_headers_transform.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
      ],
    },
    {
      'target_name': 'pe_transforms_unittests',
      'type': 'executable',
      'sources': [
        'add_debug_directory_entry_transform_unittest.cc',
        'add_imports_transform_unittest.cc',
        'add_metadata_transform_unittest.cc',
        'add_pdb_info_transform_unittest.cc',
        'explode_basic_blocks_transform_unittest.cc',
        'pe_transforms_unittests_main.cc',
        'prepare_headers_transform_unittest.cc',
      ],
      'dependencies': [
        'pe_transforms_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
