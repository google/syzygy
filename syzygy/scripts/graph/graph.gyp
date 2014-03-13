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
      'target_name': 'graph',
      'type': 'none',
      'variables': {
        'graph_sources': [
          'graph.py',
        ],
        'setup_file': 'setup.py',
        'success_file': '<(PRODUCT_DIR)/Graph-Pagefaults-egg-success.txt',
        'script_file': '<(src)/syzygy/build/build_egg.py',
      },
      'sources': [
        '<@(graph_sources)',
      ],
      'dependencies': [
        '<(src)/syzygy/py/py.gyp:virtualenv',
        '<(src)/syzygy/py/etw_db/etw_db.gyp:etw',
        '<(src)/syzygy/py/etw_db/etw_db.gyp:etw_db',
      ],
      'actions': [
        {
          'action_name': 'build_graph',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(script_file)',
            '<(setup_file)',
            '<@(graph_sources)',
          ],
          'outputs': [
            '<(success_file)',
          ],
          'action': [
            '<(PRODUCT_DIR)/py/scripts/python',
            '<(script_file)',
            '--setup-file', '<(setup_file)',
            '--build-dir', '<(PRODUCT_DIR)/temp/graph',
            '--success-file', '<(success_file)',
          ],
        },
      ],
    },
  ],
}
