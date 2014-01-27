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
      'target_name': 'wsdump_lib',
      'type': 'static_library',
      'sources': [
        'process_working_set.h',
        'process_working_set.cc'
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'wsdump_unittests',
      'type': 'executable',
      'sources': [
        'process_working_set_unittest.cc',
        'wsdump_unittests_main.cc'
      ],
      'dependencies': [
        'wsdump_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/third_party/pcre/pcre.gyp:pcre_lib',
      ],
    },
    {
      'target_name': 'wsdump',
      'type': 'executable',
      'sources': [
        'wsdump.rc',
        'wsdump_main.cc'
      ],
      'dependencies': [
        'wsdump_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/common.gyp:syzygy_version',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/third_party/pcre/pcre.gyp:pcre_lib',
      ],
    },
  ],
}
