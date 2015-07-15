# Copyright 2015 Google Inc. All Rights Reserved.
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
      'target_name': 'syzygy_version',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'syzygy_version.h',
        'version.gen.template',
      ],
      'actions': [
        {
          'action_name': 'make_version_gen',
          'inputs': [
            '<(src)/syzygy/build/template_replace.py',
            '<(src)/syzygy/SYZYGY_VERSION',
            '<(src)/syzygy/build/LASTCHANGE.gen',
            'version.gen.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/version/version.gen',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/template_replace.py',
            '--input', 'version.gen.template',
            '--output', '<(SHARED_INTERMEDIATE_DIR)/syzygy/version/version.gen',
            '<(src)/syzygy/SYZYGY_VERSION',
            '<(src)/syzygy/build/LASTCHANGE.gen',
          ],
          'process_outputs_as_sources': 1,
        },
      ],
      'all_dependent_settings': {
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)',
        ],
      },
    },
    {
      'target_name': 'version_lib',
      'type': 'static_library',
      'sources': [
        'syzygy_version.cc',
        'syzygy_version.h',
      ],
      'dependencies': [
        'syzygy_version',
      ],
      # This target exports a hard dependency because it exposes
      # files that from syzygy_version that are included from compiles.
      'hard_dependency': 1,
    },
    {
      'target_name': 'version_unittests',
      'type': 'executable',
      'sources': [
        'syzygy_version_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'version_lib',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
