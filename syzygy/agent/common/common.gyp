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
      'target_name': 'agent_common_lib',
      'type': 'static_library',
      'sources': [
        'agent.cc',
        'agent.h',
        'dlist.cc',
        'dlist.h',
        'dll_notifications.cc',
        'dll_notifications.h',
        'entry_frame.h',
        'process_utils.cc',
        'process_utils.h',
        'scoped_last_error_keeper.h',
        'thread_state.cc',
        'thread_state.h',
      ],
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
        '<(src)/syzygy/trace/client/client.gyp:rpc_client_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'agent_common_unittests',
      'type': 'executable',
      'sources': [
        'agent_common_unittests_main.cc',
        'dlist_unittest.cc',
        'dll_notifications_unittest.cc',
        'process_utils_unittest.cc',
        'thread_state_unittest.cc',
      ],
      'dependencies': [
        'agent_common_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
