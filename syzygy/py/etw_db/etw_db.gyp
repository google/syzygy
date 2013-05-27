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
      # Temporary build configuration for the ETW module.
      # TODO(siggi): Move ETW and ETW-Db into a new top-level directory.
      'target_name': 'etw',
      'type': 'none',
      'variables': {
        'etw_sources': [
          '<(src)/sawbuck/py/etw/etw/__init__.py',
          '<(src)/sawbuck/py/etw/etw/consumer.py',
          '<(src)/sawbuck/py/etw/etw/controller.py',
          '<(src)/sawbuck/py/etw/etw/evntcons.py',
          '<(src)/sawbuck/py/etw/etw/evntrace.py',
          '<(src)/sawbuck/py/etw/etw/guiddef.py',
          '<(src)/sawbuck/py/etw/etw/provider.py',
          '<(src)/sawbuck/py/etw/etw/util.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/__init__.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/binary_buffer.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/event.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/field.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/fileio.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/image.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/pagefault.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/pagefault_xp.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/process.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/registry.py',
          '<(src)/sawbuck/py/etw/etw/descriptors/thread.py',
        ],
        'setup_file': '<(src)/sawbuck/py/etw/setup.py',
        'success_file': '<(PRODUCT_DIR)/ETW-egg-success.txt',
        'script_file': '<(src)/syzygy/build/build_egg.py',
      },
      'sources': [
        '<(script_file)',
        '<(setup_file)',
        '<@(etw_sources)',
      ],
      'dependencies': [
        '<(src)/syzygy/py/py.gyp:virtualenv',
      ],
      'actions': [
        {
          'action_name': 'build_etw',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(script_file)',
            '<(setup_file)',
            '<@(etw_sources)',
          ],
          'outputs': [
            '<(success_file)',
          ],
          'action': [
            '"<(PRODUCT_DIR)/py/scripts/python"',
            '<(script_file)',
            '--setup-file', '<(setup_file)',
            '--build-dir', '<(PRODUCT_DIR)/temp/etw',
            '--success-file', '<(success_file)',
          ],
        },
      ],
    },
    {
      'target_name': 'etw_db',
      'type': 'none',
      'variables': {
        'etw_db_sources': [
          'etw_db/file.py',
          'etw_db/module.py',
          'etw_db/process.py',
          'etw_db/__init__.py',
        ],
        'setup_file': 'setup.py',
        'success_file': '<(PRODUCT_DIR)/ETW-Db-egg-success.txt',
        'script_file': '<(src)/syzygy/build/build_egg.py',
      },
      'sources': [
        '<@(etw_db_sources)',
      ],
      'dependencies': [
        'etw',
        '<(src)/syzygy/py/py.gyp:virtualenv',
      ],
      'actions': [
        {
          'action_name': 'build_etw_db',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(script_file)',
            '<(setup_file)',
            '<@(etw_db_sources)',
          ],
          'outputs': [
            '<(success_file)',
          ],
          'action': [
            '"<(PRODUCT_DIR)/py/scripts/python"',
            '<(script_file)',
            '--setup-file', '<(setup_file)',
            '--build-dir', '<(PRODUCT_DIR)/temp/etw_db',
            '--success-file', '<(success_file)',
          ],
        },
      ],

    },
  ],
}
