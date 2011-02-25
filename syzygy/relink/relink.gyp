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
      'target_name': 'relink',
      'type': 'executable',
      'sources': [
        'relink.cc',
      ],
      'dependencies': [
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/distorm/distorm.gyp:distorm',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--input-dll=$(OutDir)\\test_dll.dll',
          '--input-pdb=$(OutDir)\\test_dll.pdb',
          '--output-dll=$(OutDir)\\randomized_test_dll.dll',
          '--output-pdb=$(OutDir)\\randomized_test_dll.pdb',
        ]
      },
    },
  ],
}
