# Copyright 2012 Google Inc.
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
      'target_name': 'block_graph_lib',
      'type': 'static_library',
      'sources': [
        'basic_block.cc',
        'basic_block.h',
        'basic_block_subgraph.cc',
        'basic_block_subgraph.h',
        'block_graph.cc',
        'block_graph.h',
        'block_graph_serializer.cc',
        'block_graph_serializer.h',
        'iterate.cc',
        'iterate.h',
        'ordered_block_graph.cc',
        'ordered_block_graph.h',
        'ordered_block_graph_internal.h',
        'orderer.h',
        'transform.cc',
        'transform.h',
        'typed_block.h',
        'typed_block_internal.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'block_graph_unittest_lib',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        'block_graph_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'block_graph_unittests',
      'type': 'executable',
      'sources': [
        'basic_block_unittest.cc',
        'basic_block_subgraph_unittest.cc',
        'block_graph_serializer_unittest.cc',
        'block_graph_unittest.cc',
        'block_graph_unittests_main.cc',
        'iterate_unittest.cc',
        'ordered_block_graph_unittest.cc',
        'transform_unittest.cc',
        'typed_block_unittest.cc',
      ],
      'dependencies': [
        'block_graph_lib',
        'block_graph_unittest_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
