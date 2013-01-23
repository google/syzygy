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
      'target_name': 'block_graph_transforms_lib',
      'type': 'none',
      'sources': [
        'iterative_transform.h',
        'named_transform.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'block_graph_transforms_unittests',
      'type': 'executable',
      'sources': [
        'block_graph_transforms_unittests_main.cc',
        'iterative_transform_unittest.cc',
        'named_transform_unittest.cc',
      ],
      'dependencies': [
        'block_graph_transforms_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_unittest_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
