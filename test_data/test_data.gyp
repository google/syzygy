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
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'directory',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'actions': [
        {
          'action_name': 'make_test_data_dir',
          'inputs': [
          ],
          'outputs': [
            '$(OutDir)/test_data',
          ],
          'action': [
            'if not exist $(OutDir)/test_data mkdir $(OutDir)/test_data',
          ],
        },
      ],
    },
    {
      'target_name': 'test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '../pe/pe.gyp:test_dll',
        'directory',
      ],
      'copies': [
        {
          'destination': '$(OutDir)/test_data',
          'files': [
            '$(OutDir)/test_dll.dll',
            '$(OutDir)/test_dll.pdb',
          ],
        },
      ],
    },
    {
      'target_name': 'instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '../instrument/instrument.gyp:instrument',
        'test_dll',
      ],
      'actions': [
        {
          'action_name': 'instrument_test_data_test_dll',
          'inputs': [
            '$(OutDir)/instrument.exe',
            '$(OutDir)/test_data/test_dll.dll',
          ],
          'outputs': [
            '$(OutDir)/test_data/instrumented_test_dll.dll',
          ],
          'action': [
            '$(OutDir)/instrument.exe',
            '--input-dll=$(OutDir)/test_data/test_dll.dll',
            '--output-dll=$(OutDir)/test_data/instrumented_test_dll.dll',
          ],
        },
      ],
    },
  ],
}
