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
      'target_name': 'pdb_lib',
      'type': 'static_library',
      'sources': [
        'omap.cc',
        'omap.h',
        'pdb_byte_stream.cc',
        'pdb_byte_stream.h',
        'pdb_constants.cc',
        'pdb_constants.h',
        'pdb_data.cc',
        'pdb_data.h',
        'pdb_file_stream.cc',
        'pdb_file_stream.h',
        'pdb_reader.cc',
        'pdb_reader.h',
        'pdb_stream.cc',
        'pdb_stream.h',
        'pdb_util.cc',
        'pdb_util.h',
        'pdb_writer.cc',
        'pdb_writer.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
      ],
    },
    {
      'target_name': 'pdb_unittests',
      'type': 'executable',
      'sources': [
        'omap_unittest.cc',
        'pdb_byte_stream_unittest.cc',
        'pdb_file_stream_unittest.cc',
        'pdb_reader_unittest.cc',
        'pdb_stream_unittest.cc',
        'pdb_util_unittest.cc',
        'pdb_unittests_main.cc',
        'pdb_writer_unittest.cc',
      ],
      'dependencies': [
        'pdb_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'pdb_dump',
      'type': 'executable',
      'sources': [
        'pdb_dump_main.cc',
      ],
      'dependencies': [
        'pdb_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
