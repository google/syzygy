# Copyright 2011 Google Inc.
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
      'target_name': 'sawdust_version',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'version.gen.template',
      ],
      'actions': [
        {
          'action_name': 'make_version_gen',
          'inputs': [
            '<(DEPTH)/sawbuck/tools/template_replace.py',
            '../VERSION',
            'version.gen.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/version.gen',
          ],
          'action': [
            'python',
            '<(DEPTH)/sawbuck/tools/template_replace.py',
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
      'target_name': 'Sawdust',
      'type': 'executable',
      'sources': [
        'resource.h',
        'app_module.cc',
        'app.rc',
        'version.rc',
      ],
      'dependencies': [
        'sawdust_version',
        'application_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/base/base.gyp:base_i18n',
        '<(DEPTH)/third_party/icu/icu.gyp:icudata',
        '<(DEPTH)/third_party/zlib/zlib.gyp:zlib',
        '<(DEPTH)/build/temp_gyp/googleurl.gyp:googleurl',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'SubSystem': 2,
          # 2 is requireAdministrator UAC level.
          'UACExecutionLevel': 2,
          'AdditionalDependencies': [
            'Comctl32.lib',
          ],
        },
        'VCManifestTool': {
          'AdditionalManifestFiles': '$(ProjectDir)\\sawdust.exe.manifest',
        },
      },
    },
    {
      'target_name': 'application_lib',
      'type': 'static_library',
      'sources': [
        'report.cc',
        'report.h',
        'sawdust_about.cc',
        'sawdust_about.h'
      ],
      'dependencies': [
        '../tracer/tracer.gyp:tracer_lib',
        '<(DEPTH)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'application_lib_unittests',
      'type': 'executable',
      'sources': [
        'report_unittest.cc',
        'sawdust_about_unittest.cc',
        'application_unittest_main.cc',
      ],
      'dependencies': [
        'application_lib',
        '../tracer/tracer.gyp:tracer_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/third_party/zlib/zlib.gyp:*',
        '<(DEPTH)/build/temp_gyp/googleurl.gyp:googleurl',
      ]
    }
  ]
}
