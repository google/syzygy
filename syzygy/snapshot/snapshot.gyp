# Copyright 2010 Google Inc. All Rights Reserved.
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
      'target_name': 'run_in_snapshot',
      'type': 'executable',
      'sources': [
        'run_in_snapshot.cc'
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
      ],
      'libraries': [
        'vssapi.lib',
      ],
    },
    {
      # The XP version of this executable needs to build against the VSS SDK.
      # We bring this about by prepending the VSS SDKs to the include and
      # library paths for this target.
      # Note, however that this needs the VSS SDK to be present in
      # <(src)\third_party\vsssdk72\files. If the VSS SDK is not present
      # there, the binary produced will be identical to the run_in_snapshot
      # binary, and will not successfully run on Windows XP.
      'target_name': 'run_in_snapshot_xp',
      'type': 'executable',
      'sources': [
        'run_in_snapshot.cc'
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
      ],
      'libraries': [
        'vssapi.lib',
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalIncludeDirectories+': [
            '<(src)/third_party/vsssdk72/files/inc/winxp',
          ],
        },
        'VCLinkerTool': {
          'AdditionalLibraryDirectories+': [
            '<(src)/third_party/vsssdk72/files/lib/winxp/obj/i386',
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
        '<(src)/base/base.gyp:base_win64',
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
