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
            '<(DEPTH)/build/util/lastchange.py'
          ],
          # We include a fake output target to ensure that this command
          # is always run as part of any build.
          'outputs': [
            'THIS_OUTPUT_IS_NEVER_GENERATED.TXT',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
          'action': [
            'python', '<(DEPTH)/build/util/lastchange.py',
            '-o', '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
        },
        {
          'action_name': 'make_version_gen',
          'inputs': [
            'version.gen.template',
            '<(DEPTH)/sawbuck/tools/template_replace.py',
            '<(DEPTH)/syzygy/VERSION',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/lastchange.gen',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/version.gen',
          ],
          'action': [
            'python',
            '<(DEPTH)/sawbuck/tools/template_replace.py',
            '--input', 'version.gen.template',
            '--output', '<(SHARED_INTERMEDIATE_DIR)/syzygy/common/version.gen',
            '<(DEPTH)/syzygy/VERSION',
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
        'buffer_writer.cc',
        'buffer_writer.h',
        'defs.cc',
        'defs.h',
        'logging.cc',
        'logging.h',
        'syzygy_version.cc',
        'syzygy_version.h',
      ],
      'dependencies': [
        'syzygy_version',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
      ],
      # This target exports a hard dependency because it exposes
      # files that from syzygy_version that are included from compiles.
      'hard_dependency': 1,
    },
    {
      'target_name': 'common_unittests',
      'type': 'executable',
      'sources': [
        'align_unittest.cc',
        'application_unittest.cc',
        'buffer_writer_unittest.cc',
        'common_unittests_main.cc',
        'unittest_util_unittest.cc',
        'unittest_util.h',
        'syzygy_version_unittest.cc',
      ],
      'dependencies': [
        'common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
