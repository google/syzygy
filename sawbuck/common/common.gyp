# Copyright 2011 Google Inc.
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
  'target_defaults': {
    'include_dirs': [
      '../..',
    ],
  },
  'targets': [
    {
      'target_name': 'initializing_coclass',
      'type': 'none',
      'sources': [
        'initializing_coclass.h',
        'initializing_coclass.py',
      ],
      'actions': [
        {
          'action_name': 'make_initializing_coclass',
          'msvs_cygwin_shell': 0,
          'msvs_quote_cmd': 0,
          'inputs': [
            'initializing_coclass.py',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)'
                '/sawbuck/common/initializing_coclass_gen.inl',
          ],
          'action': [
            'python',
            'initializing_coclass.py',
            '"<(SHARED_INTERMEDIATE_DIR)'
                '/sawbuck/common/initializing_coclass_gen.inl"',
          ],
        },
      ],
      # All who use this need to be able to find the .inl file we generate.
      'all_dependent_settings': {
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
      },
    },
    {
      'target_name': 'common',
      'type': 'static_library',
      'defines': [
        # This is required for ATL to use XP-safe versions of its functions.
        '_USING_V110_SDK71_',
      ],
      'dependencies': [
        'initializing_coclass',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
      ],
      'sources': [
        'buffer_parser.cc',
        'buffer_parser.h',
        'com_utils.cc',
        'com_utils.h',
        'initializing_coclass.h',
      ],
    },
    {
      'target_name': 'common_unittests',
      'type': 'executable',
      'sources': [
        'buffer_parser_unittest.cc',
        'com_utils_unittest.cc',
        'common_unittest_main.cc',
        'initializing_coclass_unittest.cc',
      ],
      'dependencies': [
        'common',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    }
  ]
}
