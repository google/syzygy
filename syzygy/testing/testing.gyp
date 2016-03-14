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
    # The $(VCInstallDir) already contains a trailing slash, so we don't
    # need to emit one.
    'vc_vars_all_path': '$(VCInstallDir)../win_sdk/bin/SetEnv.cmd',
  },
  'targets': [
    {
      'target_name': 'toolchain_paths',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        '<(src)/syzygy/build/variable_expansion.py',
        'toolchain_paths.gen.template',
        'toolchain_wrapper.bat.template',
      ],
      'actions': [
        {
          'action_name': 'make_toolchain_wrapper.bat',
          'inputs': [
            '<(src)/syzygy/build/variable_expansion.py',
            '<(src)/syzygy/testing/toolchain_wrapper.bat.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/testing/toolchain_wrapper.bat',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/variable_expansion.py',
            '--input=<(src)/syzygy/testing/'
                'toolchain_wrapper.bat.template',
            '--output=<(SHARED_INTERMEDIATE_DIR)/syzygy/testing/'
                'toolchain_wrapper.bat',
            'VCVARSALL=<@(vc_vars_all_path)',
          ],
          'process_outputs_as_sources': 1,
        },
        {
          'action_name': 'make_toolchain_paths.gen',
          'inputs': [
            '<(src)/syzygy/build/variable_expansion.py',
            '<(src)/syzygy/testing/toolchain_paths.gen.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/testing/toolchain_paths.gen',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/variable_expansion.py',
            '--input=<(src)/syzygy/testing/'
                'toolchain_paths.gen.template',
            '--output=<(SHARED_INTERMEDIATE_DIR)/syzygy/testing/'
                'toolchain_paths.gen',
            'TOOLCHAIN_WRAPPER_PATH=<(SHARED_INTERMEDIATE_DIR)/syzygy/testing/'
                'toolchain_wrapper.bat',
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
      'target_name': 'testing_lib',
      'type': 'static_library',
      'sources': [
        'laa.cc',
        'laa.h',
        'metrics.cc',
        'metrics.h',
        'toolchain.cc',
        'toolchain.h',
      ],
      'dependencies': [
        'toolchain_paths',
        '<(src)/base/base.gyp:base',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/version/version.gyp:version_lib',
      ],
      'hard_dependency': 1,
    },
  ],
}
