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
      'target_name': 'asan_rtl_lib',
      'type': 'static_library',
      'sources': [
        'asan_shadow.cc',
        'asan_shadow.h',
      ],
    },
    {
      'target_name': 'asan_rtl_unittests',
      'type': 'executable',
      'sources': [
        'asan_shadow_unittest.cc',
        'asan_rtl_unittests_main.cc',
      ],
      'dependencies': [
        'asan_rtl_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
       ],
    },
  ],
}
