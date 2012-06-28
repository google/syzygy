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
      'target_name': 'pdb_lib',
      'type': 'static_library',
      'sources': [
        'cvinfo_ext.h',
        'omap.cc',
        'omap.h',
        'pdb_byte_stream.cc',
        'pdb_byte_stream.h',
        'pdb_constants.cc',
        'pdb_constants.h',
        'pdb_data.cc',
        'pdb_data.h',
        'pdb_dbi_stream.cc',
        'pdb_dbi_stream.h',
        'pdb_dump.cc',
        'pdb_dump.h',
        'pdb_dump_util.cc',
        'pdb_dump_util.h',
        'pdb_file.cc',
        'pdb_file.h',
        'pdb_file_stream.cc',
        'pdb_file_stream.h',
        'pdb_reader.cc',
        'pdb_reader.h',
        'pdb_stream.cc',
        'pdb_stream.h',
        'pdb_symbol_record_stream.cc',
        'pdb_symbol_record_stream.h',
        'pdb_type_info_stream.cc',
        'pdb_type_info_stream.h',
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
      'target_name': 'pdb_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
    },
    {
      'target_name': 'pdb_unittests',
      'type': 'executable',
      'sources': [
        'omap_unittest.cc',
        'pdb_byte_stream_unittest.cc',
        'pdb_file_stream_unittest.cc',
        'pdb_file_unittest.cc',
        'pdb_dump_unittest.cc',
        'pdb_reader_unittest.cc',
        'pdb_stream_unittest.cc',
        'pdb_symbol_record_stream_unittest.cc',
        'pdb_type_info_stream_unittest.cc',
        'pdb_util_unittest.cc',
        'pdb_unittests_main.cc',
        'pdb_writer_unittest.cc',
      ],
      'dependencies': [
        'pdb_lib',
        'pdb_unittest_utils',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(DEPTH)/syzygy/test_data/test_data.gyp:test_dll',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
      'libraries': [
        'imagehlp.lib',
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
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
