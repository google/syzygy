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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'reorder_lib',
      'type': 'static_library',
      'sources': [
        'comdat_order.cc',
        'comdat_order.h',
        'linear_order_generator.cc',
        'linear_order_generator.h',
        'reorderer.cc',
        'reorderer.h',
      ],
      'dependencies': [
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/call_trace/call_trace.gyp:call_trace_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
      ],
    },
    {
      'target_name': 'reorder',
      'type': 'executable',
      'sources': [
        'reorder_main.cc',
      ],
      'dependencies': [
        'reorder_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--input-dll=..\\reorder\\test_data\\test_dll.dll',
          '--instrumented-dll=$(OutDir)\\instrumented_test_dll.dll',
          '--output-order=$(OutDir)\\test_dll_order.json',
          '--output-comdats=$(OutDir)\\test_dll_comdats.txt',
          '--output-stats',
          '--reorderer-flags=reorder-data',
          '--pretty-print',
          '..\\reorder\\test_data\\call_trace.etl',
          '..\\reorder\\test_data\\kernel.etl',
        ]
      },
    },
  ],
}
