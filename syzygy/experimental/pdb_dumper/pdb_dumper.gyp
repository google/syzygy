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
      'target_name': 'pdb_dumper_lib',
      'type': 'static_library',
      'sources': [
        'pdb_dump.cc',
        'pdb_dump.h',
        'pdb_dump_util.cc',
        'pdb_dump_util.h',
        'pdb_leaf.cc',
        'pdb_leaf.h',
        'pdb_module_info_stream_dumper.cc',
        'pdb_module_info_stream_dumper.h',
        'pdb_symbol_record_dumper.cc',
        'pdb_symbol_record_dumper.h',
        'pdb_type_info_stream_dumper.cc',
        'pdb_type_info_stream_dumper.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
      ],
    },
    {
      'target_name': 'pdb_dumper',
      'type': 'executable',
      'sources': [
        'pdb_dump_main.cc',
      ],
      'dependencies': [
        'pdb_dumper_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
    },
  ],
}
