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
      'target_name': 'agent_common_lib',
      'type': 'static_library',
      'sources': [
        'entry_frame.h',
        'process_utils.cc',
        'process_utils.h',
        'scoped_last_error_keeper.h',
      ],
      'dependencies': [
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/trace/client/client.gyp:rpc_client_lib',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'agent_common_unittests',
      'type': 'executable',
      'sources': [
        'agent_common_unittests_main.cc',
        'process_utils_unittest.cc',
      ],
      'dependencies': [
        'agent_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(DEPTH)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
