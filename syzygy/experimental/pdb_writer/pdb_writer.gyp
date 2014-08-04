# Copyright 2014 Google Inc. All Rights Reserved.
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
      'target_name': 'pdb_writer_lib',
      'type': 'static_library',
      'sources': [
        'pdb_debug_info_stream_writer.cc',
        'pdb_debug_info_stream_writer.h',
        'pdb_header_stream_writer.cc',
        'pdb_header_stream_writer.h',
        'pdb_section_header_stream_writer.cc',
        'pdb_section_header_stream_writer.h',
        'pdb_string_table_writer.cc',
        'pdb_string_table_writer.h',
        'pdb_type_info_stream_writer.cc',
        'pdb_type_info_stream_writer.h',
        'symbol.cc',
        'symbol.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
      ],
    },
    {
      'target_name': 'pdb_writer_unittests',
      'type': 'executable',
      'sources': [
        'pdb_string_table_writer_unittest.cc',
        'pdb_writer_unittests_main.cc',
      ],
      'dependencies': [
        'pdb_writer_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
