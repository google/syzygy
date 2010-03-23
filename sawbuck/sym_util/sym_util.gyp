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
  'includes': [
    '../../build/common.gypi',
  ],
  'target_defaults': {
    'include_dirs': [
      '../..',
    ],
    'defines': [
      # Wide char debug help.
      'DBGHELP_TRANSLATE_TCHAR',
    ],
  },
  'targets': [
    {
      'target_name': 'sym_util',
      'type': 'static_library',
      'sources': [
        'module_cache.cc',
        'module_cache.h',
        'symbol_cache.cc',
        'symbol_cache.h',
        'types.cc',
        'types.h',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],
    },
    {
      'target_name': 'sym_util_unittests',
      'type': 'executable',
      'sources': [
        'module_cache_unittest.cc',
      ],
      'dependencies': [
        'sym_util',
        '../../base/base.gyp:base',
        '../../testing/gtest.gyp:gtest',
      ],
    },
  ]
}
