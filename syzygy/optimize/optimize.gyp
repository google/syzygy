# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
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
      'target_name': 'optimize_lib',
      'type': 'static_library',
      'sources': [
        'optimize_app.cc',
        'optimize_app.h',
        'application_profile.cc',
        'application_profile.h',
        'transforms/inlining_transform.cc',
        'transforms/inlining_transform.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/sawbuck/common/common.gyp:common',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/grinder/grinder.gyp:grinder_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
      ],
    },
    {
      'target_name': 'optimize',
      'type': 'executable',
      'sources': [
        'optimize_main.cc',
        'optimize.rc',
      ],
      'dependencies': [
        'optimize_lib',
      ],
    },
    {
      'target_name': 'optimize_unittests',
      'type': 'executable',
      'sources': [
        'application_profile_unittest.cc',
        'optimize_app_unittest.cc',
        'optimize_unittests_main.cc',
        'transforms/inlining_transform_unittest.cc',
      ],
      'dependencies': [
        'optimize_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
        '<(src)/syzygy/test_data/test_data.gyp:test_dll_order_json',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    }
  ],
}
