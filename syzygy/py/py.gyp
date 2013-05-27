# Copyright 2011 Google Inc. All Rights Reserved.
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
      'target_name': 'build_py_libs',
      'type': 'none',
      'dependencies': [
        'etw_db/etw_db.gyp:etw_db',
      ],
    },
    {
      # This creates a new python installation in the "py" subdir of the
      # current configuration's output directory.
      'target_name': 'virtualenv',
      'type': 'none',
      'actions': [
        {
          'action_name': 'create_virtualenv',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(src)/syzygy/build/create_virtualenv.py',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/virtualenv-created.txt',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/create_virtualenv.py',
            '--output-dir', '<(PRODUCT_DIR)/py',
            '--success-file', '<(PRODUCT_DIR)/virtualenv-created.txt',
          ],
        },
      ],
    },
  ],
}
