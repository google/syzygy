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
      'target_name': 'syzygy_version',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'syzygy_version.h',
        'version.gen.template',
      ],
      'actions': [
        {
          'action_name': 'make_lastchange_gen',
          'inputs': [
            '<(src)/build/util/lastchange.py'
          ],
          # We include a fake output target to ensure that this command
          # is always run as part of any build.
          'outputs': [
            'THIS_OUTPUT_IS_NEVER_GENERATED.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
          'action': [
            '<(python_exe)', '<(src)/build/util/lastchange.py',
            '-s', '<(src)/syzygy',
            '-o', '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
        },
        {
          'action_name': 'make_version_gen',
          'inputs': [
            'version.gen.template',
            '<(src)/sawbuck/tools/template_replace.py',
            '<(src)/syzygy/VERSION',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/version.gen',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/sawbuck/tools/template_replace.py',
            '--input', 'version.gen.template',
            '--output', '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/version.gen',
            '<(src)/syzygy/VERSION',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
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
      'target_name': 'common_lib',
      'type': 'static_library',
      'sources': [
        'align.cc',
        'align.h',
        'application.cc',
        'application.h',
        'application_impl.h',
        'assertions.h',
        'buffer_writer.cc',
        'buffer_writer.h',
        'com_utils.cc',
        'com_utils.h',
        'comparable.h',
        'dbghelp_util.cc',
        'dbghelp_util.h',
        'defs.cc',
        'defs.h',
        'indexed_frequency_data.cc',
        'indexed_frequency_data.h',
        'logging.cc',
        'logging.h',
        'path_util.cc',
        'path_util.h',
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
      'target_name': 'common_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'common_unittests',
      'type': 'executable',
      'sources': [
        'align_unittest.cc',
        'application_unittest.cc',
        'buffer_writer_unittest.cc',
        'com_utils_unittest.cc',
        'common_unittests_main.cc',
        'comparable_unittest.cc',
        'path_util_unittest.cc',
        'unittest_util_unittest.cc',
        'syzygy_version_unittest.cc',
      ],
      'dependencies': [
        'common_lib',
        'common_unittest_utils',
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
