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
      # Change this to static_library once there's at least one
      # CC file in the target.
      'type': 'none',
      'sources': [
        'shadow_stack.h',
      ],
      'dependencies': [
        '<(DEPTH)/syzygy/trace/rpc/rpc.gyp:rpc_common_lib',
      ],
    },
    {
      'target_name': 'agent_common_unittests',
      'type': 'executable',
      'sources': [
        'agent_common_unittests_main.cc',
        'shadow_stack_unittest.cc',
      ],
      'dependencies': [
        'agent_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
  ],
}
