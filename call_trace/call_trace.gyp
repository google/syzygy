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
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'call_trace_lib',
      'type': 'static_library',
      'sources': [
        'call_trace_control.h',
        'call_trace_control.cc',
        'call_trace_defs.h',
        'call_trace_defs.cc',
        'call_trace_parser.h',
        'call_trace_parser.cc',
      ],
    },
    {
      'target_name': 'call_trace_unittests',
      'type': 'executable',
      'sources': [
        'call_trace_dll_unittest.cc',
        'call_trace_unittests_main.cc',
      ],
      'dependencies': [
        'call_trace_lib',
        'call_trace',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],      
    },
    {
      'target_name': 'call_trace',
      'type': 'shared_library',
      'sources': [
        'call_trace.def',
        'call_trace_defs.h',
        'call_trace_main.h',
        'call_trace_main.cc',
      ],
      'dependencies': [
        'call_trace_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],      
    },
    {
      'target_name': 'call_trace_viewer',
      'type': 'executable',
      'sources': [
        'call_trace_defs.h',
        'call_trace_viewer_main.cc',
      ],
      'dependencies': [
        'call_trace_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],      
    }
  ]
}
