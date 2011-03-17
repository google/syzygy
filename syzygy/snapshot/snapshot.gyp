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
      'target_name': 'run_in_snapshot',
      'type': 'executable',
      'sources': [
        'run_in_snapshot.cc'
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
      'libraries': [
        'vssapi.lib',
      ],
    },
    {
      # The XP version of this executable needs to build against the VSS SDK.
      # We bring this about by changing the include and library settings for
      # this target. Note, however that this needs the VSS SDK to be installed
      # in the default location at C:\Program Files (x86)\Microsoft\VSSSDK72.
      'target_name': 'run_in_snapshot_xp',
      'type': 'executable',
      'sources': [
        'run_in_snapshot.cc'
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
      'libraries': [
        'vssapi.lib',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalIncludeDirectories': [
            'C:\Program Files (x86)\Microsoft\VSSSDK72\inc\winxp',
          ],
        },
        'VCLinkerTool': {
          'AdditionalLibraryDirectories': [
            'C:\Program Files (x86)\Microsoft\VSSSDK72\lib\winxp\obj\i386',
          ],
          'AdditionalDependencies': [
            'vssapi.lib',
          ],
        },
      },
    },
    {
      # For Vista/Win7 x64 installs we need an x64 executable. Even though the
      # API is very COM-like, it won't cross the bitness divide for us.
      'target_name': 'run_in_snapshot_x64',
      'type': 'executable',
      'sources': [
        'run_in_snapshot.cc'
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base_nacl_win64',
      ],
      'libraries': [
        'vssapi.lib',
      ],
      'configurations': {
        'Common_Base': {
          'msvs_target_platform': 'x64',
        },
      },
    },
  ]
}
