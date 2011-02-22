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
  'targets': [
    {
      'target_name': 'build_all',
      'type': 'none',
      'dependencies': [
        'core/core.gyp:*',
        'pdb/pdb.gyp:*',
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
          '<(DEPTH)/syzygy/core/core.gyp:core_unittests',
          '<(DEPTH)/syzygy/pdb/pdb.gyp:pdb_unittests',
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
            '../sawbuck/tools/run_unittests.py',
            '../sawbuck/tools/verifier.py',
            '<(PRODUCT_DIR)/pdb_unittests.exe',
          ],
          'outputs': [
            # Created only if all unittests succeed
            '<(success_file)',
          ],
          'action': [
            '<(DEPTH)/third_party/python_24/python',
            '../sawbuck/tools/run_unittests.py',
            '--exe-dir=<(PRODUCT_DIR)',
            '--success-file=<(success_file)',
            '<@(unittest_targets)',
          ],
        },
      ],
    }
  ]
}
