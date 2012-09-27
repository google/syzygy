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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'timed_decomposer_lib',
      'type': 'static_library',
      'sources': [
        'timed_decomposer_app.cc',
        'timed_decomposer_app.h',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/common/common.gyp:syzygy_version',
      ],
    },
    {
      'target_name': 'timed_decomposer',
      'type': 'executable',
      'sources': [
        'timed_decomposer_main.cc',
      ],
      'dependencies': [
        'timed_decomposer_lib',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--image=$(OutDir)\\test_dll.dll',
          '--csv=$(OutDir)\\decomposition_times_for_test_dll.csv',
          '--iterations=20',
        ],
      },
    },
  ],
}
