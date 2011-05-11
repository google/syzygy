# Copyright 2011 Google Inc.
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
    'chromium_code': 1,  # Include build/common.gypi (for warning levels etc.).
  },
  'targets': [
    {
      'target_name': 'build_all',
      'type': 'none',
      'dependencies': [
        '<(DEPTH)/base/base.gyp:*',
        'installer/installer.gyp:*',
        'app/app.gyp:*',
        'tracer/tracer.gyp:*',
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
          '<(DEPTH)/sawdust/tracer/tracer.gyp:tracer_lib_unittests',
          '<(DEPTH)/sawdust/app/app.gyp:application_lib_unittests',
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
            '<(PRODUCT_DIR)/tracer_lib_unittests.exe',
            '<(PRODUCT_DIR)/application_lib_unittests.exe',
          ],
          'outputs': [
            # Created only if all unittests succeed
            '<(success_file)',
          ],
          'action': [
            '<(DEPTH)/third_party/python_26/python',
            '../sawbuck/tools/run_unittests.py',
            '--exe-dir=<(PRODUCT_DIR)',
            '--success-file=<(success_file)',
            # SymSrv.dll abandons a critical section on
            # unlock on 32 bit systems
            '--exception="dbghelp!SymCleanup,Locks,0x201"',
            '--exception="dbghelp!SymCleanup,Locks,0x211"',
            '<@(unittest_targets)',
          ],
        },
      ],
    }
  ]
}
