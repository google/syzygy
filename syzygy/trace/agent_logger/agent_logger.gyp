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
      'target_name': 'agent_logger_lib',
      'type': 'static_library',
      'sources': [
        'agent_logger.cc',
        'agent_logger.h',
        'agent_logger_app.cc',
        'agent_logger_app.h',
        'agent_logger_rpc_impl.cc',
        'agent_logger_rpc_impl.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
      ],
    },
    {
      'target_name': 'agent_logger_unittests',
      'type': 'executable',
      'sources': [
        'agent_logger_app_unittest.cc',
        'agent_logger_unittest.cc',
        'agent_logger_unittests_main.cc',
      ],
      'dependencies': [
        'agent_logger_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
      ],
    },
    {
      'target_name': 'agent_logger',
      'type': 'executable',
      'sources': [
        'agent_logger_main.cc',
        'agent_logger.rc',
      ],
      'dependencies': [
        'agent_logger_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
    },
  ],
}
