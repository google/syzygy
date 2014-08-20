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
      'target_name': 'coverage_client',
      'type': 'loadable_module',
      'includes': ['../agent.gypi'],
      'sources': [
        'coverage.cc',
        'coverage.def',
        'coverage.h',
        'coverage.rc',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:call_trace_rpc_lib',
        '<(src)/syzygy/trace/client/client.gyp:rpc_client_lib',
      ],
    },
    {
      'target_name': 'coverage_unittests',
      'type': 'executable',
      'sources': [
        'coverage_unittest.cc',
        'coverage_unittests_main.cc',
      ],
      'dependencies': [
        'coverage_client',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
       ],
    },
  ],
}
