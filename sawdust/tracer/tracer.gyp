# Copyright 2009 Google Inc.
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
      '../..',
    ],
  },
  'targets': [
    {
      'target_name': 'tracer_lib',
      'type': 'static_library',
      'sources': [
        'configuration.h',
        'configuration.cc',
        'registry.h',
        'registry.cc',
        'system_info.h',
        'system_info.cc',
        'upload.h',
        'upload.cc',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'tracer_lib_unittests',
      'type': 'executable',
      'sources': [
        'configuration_unittest.cc',
        'configuration_unittest_data.json',
        'configuration_unittest_expressions.json',
        'registry_unittest.cc',
        'system_info_unittest.cc',
        'tracer_unittest_main.cc',
        'tracer_unittest_util.h',
        'tracer_unittest_util.cc',
        'upload_unittest.cc',
      ],
      'dependencies': [
        'tracer_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/third_party/zlib/zlib.gyp:*',
        '<(DEPTH)/build/temp_gyp/googleurl.gyp:googleurl',
      ],
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            'configuration_unittest_data.json',
            'configuration_unittest_expressions.json'
          ]
        },
      ],
    },
  ]
}
