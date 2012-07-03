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
#
# This include file will be in force for all gyp files processed in the
# Syzygy tree.

{
  'target_defaults': {
    'msvs_settings': {
      'VCLinkerTool': {
        # Enable support for large address spaces.
        'LargeAddressAware': 2,
      },
    },
    'configurations': {
      # A coverage build is for all intents and purposes a debug build with
      # profile information (and therefore no incremental linking). This allows
      # it to be instrumented.
      'Coverage_Base': {
        'abstract': 1,
        'inherit_from': ['Debug_Base'],
        'defines': [
          # This global define is in addition to _DEBUG.
          '_COVERAGE_BUILD',
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
          },
          'VCLinkerTool': {
            # 0: inherit, 1: disabled, 2: enabled.
            'LinkIncremental': '1',
            # This corresponds to the /PROFILE flag, which enables the
            # resulting binaries to be instrumented by vsinstr.exe.
            'Profile': 'true',
          },
        },
      },
      'Coverage': {
        'inherit_from': ['Common_Base', 'x86_Base', 'Coverage_Base'],
      },
      'conditions': [
        ['OS=="win"', {
          'Coverage_x64': {
            'inherit_from': ['Common_Base', 'x64_Base', 'Coverage_Base'],
          },
        }],
      ],
    },
  },
}
