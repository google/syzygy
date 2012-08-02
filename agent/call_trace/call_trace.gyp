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
      'target_name': 'call_trace_client',
      'type': 'shared_library',
      'sources': [
        'client_rpc.cc',
        'client_rpc.def',
        'client_rpc.h',
        'client_rpc.rc',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:syzygy_version',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
        '<(DEPTH)/syzygy/trace/client/client.gyp:rpc_client_lib',
       ],
     },
  ],
}
