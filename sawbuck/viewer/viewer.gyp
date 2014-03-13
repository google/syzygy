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
      '<(DEPTH)/third_party/wtl/include',
    ],
    'defines': [
      '_WTL_NO_CSTRING',
    ],
  },
  'targets': [
    {
      'target_name': 'sawbuck_version',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'version.gen.template',
      ],
      'actions': [
        {
          'action_name': 'make_version_gen',
          'inputs': [
            '../tools/template_replace.py',
            '../VERSION',
            'version.gen.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/version.gen',
          ],
          'action': [
            'python',
            '../tools/template_replace.py',
            '--input', 'version.gen.template',
            '--output', '<(SHARED_INTERMEDIATE_DIR)/version.gen',
            '../VERSION',
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
      'target_name': 'viewer_lib',
      'type': 'static_library',
      'sources': [
        'const_config.h',
        'filter.cc',
        'filter.h',
        'filter_dialog.cc',
        'filter_dialog.h',
        'filtered_log_view.cc',
        'filtered_log_view.h',
        'find_dialog.cc',
        'find_dialog.h',
        'log_viewer.h',
        'log_viewer.cc',
        'log_list_view.h',
        'log_list_view.cc',
        'preferences.cc',
        'preferences.h',
        'provider_configuration.cc',
        'provider_configuration.h',
        'provider_dialog.cc',
        'provider_dialog.h',
        'sawbuck_guids.h',
        'stack_trace_list_view.h',
        'stack_trace_list_view.cc',
        'viewer_window.cc',
        'viewer_window.h',
      ],
      'dependencies': [
        '../log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/third_party/pcre/pcre.gyp:pcre_lib',
      ],
    },
    {
      # Our tests and sawbuck.exe need the dbghelp and symsrv
      # DLLs in their parent directory, this copies them there.
      'target_name': 'copy_dlls',
      'type': 'none',
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '<(DEPTH)/third_party/debugging_tools/files/dbghelp.dll',
            '<(DEPTH)/third_party/debugging_tools/files/symsrv.dll',
          ],
        },
      ],
    },
    {
      'target_name': 'sawbuck_exe',
      'product_name': 'Sawbuck',
      'type': 'executable',
      'sources': [
        'resource.h',
        'viewer_module.cc',
        'viewer_module.h',
        'viewer.rc',
        'version.rc',
      ],
      'dependencies': [
        'copy_dlls',
        'sawbuck_version',
        'viewer_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/base/base.gyp:base_i18n',
        '<(DEPTH)/third_party/icu/icu.gyp:icudata',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'SubSystem': 2,
          # 2 is requireAdministrator UAC level.
          'UACExecutionLevel': 2,
          # This corresponds to /PROFILE, which ensures that the
          # PDB file contains a FIXUP stream.
          'Profile': 'true',
        },
        'VCManifestTool': {
          'AdditionalManifestFiles': '$(ProjectDir)\\sawbuck.exe.manifest',
        },
      },
    },
    {
      'target_name': 'viewer_unittests',
      'type': 'executable',
      'sources': [
        'filter_unittest.cc',
        'filtered_log_view_unittest.cc',
        'preferences_unittest.cc',
        'provider_configuration_unittest.cc',
        'registry_test.h',
        'registry_test.cc',
        'sawbuck_guids.h',
        'viewer_unittest_main.cc',
        'viewer_window_unittest.cc',
        'viewer.rc',
      ],
      'dependencies': [
        'copy_dlls',
        'viewer_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/base/base.gyp:base_i18n',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
      ],
    },
  ]
}
