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
      'target_name': 'pdb_lib',
      'type': 'static_library',
      'sources': [
        'mutators/add_named_stream_mutator.h',
        'mutators/named_mutator.h',
        'omap.cc',
        'omap.h',
        'pdb_byte_stream.cc',
        'pdb_byte_stream.h',
        'pdb_constants.cc',
        'pdb_constants.h',
        'pdb_data.cc',
        'pdb_data.h',
        'pdb_data_types.h',
        'pdb_dbi_stream.cc',
        'pdb_dbi_stream.h',
        'pdb_file.cc',
        'pdb_file.h',
        'pdb_file_stream.cc',
        'pdb_file_stream.h',
        'pdb_mutator.cc',
        'pdb_mutator.h',
        'pdb_reader.cc',
        'pdb_reader.h',
        'pdb_stream.cc',
        'pdb_stream.h',
        'pdb_symbol_record.cc',
        'pdb_symbol_record.h',
        'pdb_type_info_stream.cc',
        'pdb_type_info_stream.h',
        'pdb_util.cc',
        'pdb_util.h',
        'pdb_writer.cc',
        'pdb_writer.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
    },
    {
      'target_name': 'pdb_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        'pdb_lib',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'pdb_unittests',
      'type': 'executable',
      'sources': [
        'mutators/add_named_stream_mutator_unittest.cc',
        'mutators/named_mutator_unittest.cc',
        'omap_unittest.cc',
        'pdb_byte_stream_unittest.cc',
        'pdb_dbi_stream_unittest.cc',
        'pdb_file_stream_unittest.cc',
        'pdb_file_unittest.cc',
        'pdb_mutator_unittest.cc',
        'pdb_reader_unittest.cc',
        'pdb_stream_unittest.cc',
        'pdb_symbol_record_unittest.cc',
        'pdb_type_info_stream_unittest.cc',
        'pdb_util_unittest.cc',
        'pdb_unittests_main.cc',
        'pdb_writer_unittest.cc',
      ],
      'dependencies': [
        'pdb_lib',
        'pdb_unittest_utils',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/test_data/test_data.gyp:copy_test_dll',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
