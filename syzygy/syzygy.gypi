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
  'variables': {
    'chromium_code': 1,
  },

  'target_defaults': {
    'configurations': {
      'Coverage': {
        'inherit_from': ['Debug'],
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
    },
  },
}
