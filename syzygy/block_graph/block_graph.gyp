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
      'target_name': 'block_graph_lib',
      'type': 'static_library',
      'sources': [
        'basic_block.cc',
        'basic_block.h',
        'basic_block_assembler.cc',
        'basic_block_assembler.h',
        'basic_block_decomposer.cc',
        'basic_block_decomposer.h',
        'basic_block_subgraph.cc',
        'basic_block_subgraph.h',
        'block_builder.cc',
        'block_builder.h',
        'block_graph.cc',
        'block_graph.h',
        'block_graph_serializer.cc',
        'block_graph_serializer.h',
        'block_util.cc',
        'block_util.h',
        'filter_util.cc',
        'filter_util.h',
        'filterable.cc',
        'filterable.h',
        'iterate.cc',
        'iterate.h',
        'ordered_block_graph.cc',
        'ordered_block_graph.h',
        'ordered_block_graph_internal.h',
        'orderer.cc',
        'orderer.h',
        'tags.h',
        'transform.cc',
        'transform.h',
        'transform_policy.h',
        'typed_block.h',
        'typed_block_internal.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'block_graph_unittest_lib',
      'type': 'static_library',
      'includes': ['../build/masm.gypi'],
      'sources': [
        'basic_block_assembly_func.asm',
        'basic_block_test_util.cc',
        'basic_block_test_util.h',
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        'block_graph_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'block_graph_unittests',
      'type': 'executable',
      'sources': [
        'basic_block_assembler_unittest.cc',
        'basic_block_decomposer_unittest.cc',
        'basic_block_unittest.cc',
        'basic_block_subgraph_unittest.cc',
        'block_graph_serializer_unittest.cc',
        'block_builder_unittest.cc',
        'block_graph_unittest.cc',
        'block_graph_unittests_main.cc',
        'block_util_unittest.cc',
        'filter_util_unittest.cc',
        'filterable_unittest.cc',
        'iterate_unittest.cc',
        'ordered_block_graph_unittest.cc',
        'orderer_unittest.cc',
        'transform_unittest.cc',
        'typed_block_unittest.cc',
      ],
      'dependencies': [
        'block_graph_lib',
        'block_graph_unittest_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
