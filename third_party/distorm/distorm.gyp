# Copyright 2010 Google Inc.
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
      'target_name': 'distorm',
      'type': 'static_library',
      'sources': [
        'files/config.h',
        'files/distorm.h',
        'files/mnemonics.h',
        'files/mnemonics.c',
        'files/src/insts.h',
        'files/src/operands.h',
        'files/src/decoder.h',
        'files/src/decoder.c',
        'files/src/distorm.c',
        'files/src/instructions.h',
        'files/src/instructions.c',
        'files/src/insts.c',
        'files/src/operands.c',
        'files/src/prefix.h',
        'files/src/prefix.c',
        'files/src/textdefs.h',
        'files/src/textdefs.c',
        'files/src/wstring.c',
        'files/src/wstring.h',
        'files/src/x86defs.c',
        'files/src/x86defs.h',
      ],
      'all_dependent_settings': {
        'include_dirs': [
          'files',
        ],
      },
    },
  ],
}
