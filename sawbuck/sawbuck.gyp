# Copyright 2009 Google Inc.
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
  'includes': [
    '../build/common.gypi',
  ],
  'targets': [
    {
      'target_name': 'build_all',
      'type': 'none',
      'dependencies': [
        '../base/base.gyp:*',
        'installer/installer.gyp:*',
        'sym_util/sym_util.gyp:*',
        'viewer/viewer.gyp:*',
      ],
    },
    {
      # Add new unittests to this target as inputs.
      'target_name': 'run_unittests',
      'type': 'none',
      'variables': {
        # The file that marks success of all unittests.
        'success_file': '<(PRODUCT_DIR)/unittest_success.txt',

        # Add all unit test targets here.
        'unittest_targets': [
          '<(DEPTH)/sawbuck/sym_util/sym_util.gyp:sym_util_unittests',
          '<(DEPTH)/sawbuck/viewer/viewer.gyp:log_view_unittests',
        ],
      },
      'dependencies': [
        '<@(unittest_targets)',
      ],
      'actions': [
        {
          'action_name': 'run_unittests',
          'msvs_cygwin_shell': 0,
          'inputs': [
            'tools/run_unittests.py',
            'tools/verifier.py',
            '<(PRODUCT_DIR)/sym_util_unittests.exe',
            '<(PRODUCT_DIR)/log_view_unittests.exe',
          ],
          'outputs': [
            # Created only if all unittests succeed
            '<(success_file)',
          ],
          'action': [
            'python',
            'tools/run_unittests.py',
            '--exe-dir=<(PRODUCT_DIR)',
            '--success-file=<(success_file)',
            '<@(unittest_targets)',
          ],
        },
      ],
    }
  ]
}
