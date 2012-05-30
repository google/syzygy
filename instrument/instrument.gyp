# Copyright 2012 Google Inc.
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
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      'target_name': 'instrument_lib',
      'type': 'static_library',
      'sources': [
        'instrument_app.cc',
        'instrument_app.h',
        'transforms/entry_thunk_transform.cc',
        'transforms/entry_thunk_transform.h',
      ],
      'dependencies': [
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
        '<(DEPTH)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
        '<(DEPTH)/syzygy/relink/relink.gyp:relink_lib',
      ],
    },
    {
      'target_name': 'instrument',
      'type': 'executable',
      'sources': [
        'instrument_main.cc',
        'instrumenter.rc',
      ],
      'dependencies': [
        'instrument_lib',
      ],
      'run_as': {
        'action': [
          '$(TargetPath)',
          '--overwrite',
          '--input-dll=$(OutDir)\\test_dll.dll',
          '--output-dll=$(OutDir)\\instrumented_test_dll.dll',
        ]
      },
    },
    {
      'target_name': 'instrument_unittests',
      'type': 'executable',
      'sources': [
        'instrument_app_unittest.cc',
        'instrument_unittests_main.cc',
        'transforms/entry_thunk_transform_unittest.cc',
      ],
      'dependencies': [
        'instrument_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/syzygy/core/core.gyp:core_unittest_utils',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(DEPTH)/syzygy/pe/pe.gyp:test_dll',
        '<(DEPTH)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
      ],
    },
  ],
}
