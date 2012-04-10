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
      'target_name': 'profile_lib',
      'type': 'static_library',
      'sources': [
        'return_thunk_factory.cc',
        'return_thunk_factory.h',
        'scoped_last_error_keeper.h',
      ],
    },
    {
      'target_name': 'profile_client',
      'type': 'shared_library',
      'sources': [
        'profiler.cc',
        'profiler.def',
        'profiler.h',
        'profiler.rc',
      ],
      'dependencies': [
        'profile_lib',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:syzygy_version',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
        '<(DEPTH)/syzygy/trace/client/client.gyp:rpc_client_lib',
      ],
    },
    {
      'target_name': 'profile_unittests',
      'type': 'executable',
      'sources': [
        'profiler_unittest.cc',
        'profiler_unittests_main.cc',
        'return_thunk_factory_unittest.cc',
      ],
      'dependencies': [
        'profile_client',
        'profile_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(DEPTH)/syzygy/trace/service/service.gyp:rpc_service_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
       ],
    },
  ],
}
