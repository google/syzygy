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
      'target_name': 'coverage_client',
      'type': 'shared_library',
      'sources': [
        'coverage.cc',
        'coverage.def',
        'coverage.h',
        'coverage.rc',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/common/common.gyp:syzygy_version',
        '<(DEPTH)/syzygy/core/core.gyp:core_lib',
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
        '<(DEPTH)/syzygy/trace/client/client.gyp:rpc_client_lib',
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
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(DEPTH)/syzygy/trace/parse/parse.gyp:parse_unittest_utils',
        '<(DEPTH)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(DEPTH)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
       ],
    },
  ],
}
