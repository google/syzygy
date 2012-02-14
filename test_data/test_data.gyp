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

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/pe/pe.gyp:test_dll',
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
      'target_name': 'etw_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/instrument/instrument.gyp:instrument',
        'test_dll',
      ],
      'actions': [
        {
          'action_name': 'etw_instrument_test_data_test_dll',
          'inputs': [
            '$(OutDir)/instrument.exe',
            '$(OutDir)/test_data/test_dll.dll',
          ],
          'outputs': [
            '$(OutDir)/test_data/etw_instrumented_test_dll.dll',
            '$(OutDir)/test_data/etw_instrumented_test_dll.pdb',
          ],
          'action': [
            '"$(OutDir)/instrument.exe"',
            '--call-trace-client=ETW',
            '--input-dll=$(OutDir)/test_data/test_dll.dll',
            '--output-dll=$(OutDir)/test_data/etw_instrumented_test_dll.dll',
            '--output-pdb=$(OutDir)/test_data/etw_instrumented_test_dll.pdb',
          ],
        },
      ],
    },
    {
      'target_name': 'rpc_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/instrument/instrument.gyp:instrument',
        'test_dll',
      ],
      'actions': [
        {
          'action_name': 'rpc_instrument_test_data_test_dll',
          'inputs': [
            '$(OutDir)/instrument.exe',
            '$(OutDir)/test_data/test_dll.dll',
          ],
          'outputs': [
            '$(OutDir)/test_data/rpc_instrumented_test_dll.dll',
            '$(OutDir)/test_data/rpc_instrumented_test_dll.pdb',
          ],
          'action': [
            '"$(OutDir)/instrument.exe"',
            '--call-trace-client=RPC',
            '--input-dll=$(OutDir)/test_data/test_dll.dll',
            '--output-dll=$(OutDir)/test_data/rpc_instrumented_test_dll.dll',
            '--output-pdb=$(OutDir)/test_data/rpc_instrumented_test_dll.pdb',
          ],
        },
      ],
    },
    {
      'target_name': 'randomized_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/relink/relink.gyp:relink',
        'test_dll'
      ],
      'actions': [
        {
          'action_name': 'randomize_test_data_test_dll',
          'inputs': [
            '$(OutDir)/relink.exe',
            '$(OutDir)/test_data/test_dll.dll',
          ],
          'outputs': [
            '$(OutDir)/test_data/randomized_test_dll.dll',
            '$(OutDir)/test_data/randomized_test_dll.pdb',
          ],
          'action': [
            '"$(OutDir)/relink.exe"',
            '--seed=0',
            '--input-dll=$(OutDir)/test_data/test_dll.dll',
            '--input-pdb=$(OutDir)/test_data/test_dll.pdb',
            '--output-dll=$(OutDir)/test_data/randomized_test_dll.dll',
            '--output-pdb=$(OutDir)/test_data/randomized_test_dll.pdb',
          ],
        },
      ],
    },
  ],
}
