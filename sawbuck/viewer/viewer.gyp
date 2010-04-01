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
      '../../chrome/third_party/wtl/include',
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
      'target_name': 'log_view_lib',
      'type': 'static_library',
      'sources': [
        'filtered_log_view.cc',
        'filtered_log_view.h',
        'provider_dialog.cc',
        'provider_dialog.h',
        'kernel_log_consumer.cc',
        'kernel_log_consumer.h',
        'log_consumer.h',
        'log_consumer.cc',
        'log_viewer.h',
        'log_viewer.cc',
        'log_list_view.h',
        'log_list_view.cc',
        'sawbuck_guids.h',
        'stack_trace_list_view.h',
        'stack_trace_list_view.cc',
        'symbol_lookup_service.h',
        'symbol_lookup_service.cc',
        'viewer_window.cc',
        'viewer_window.h',
      ],
      'dependencies': [
        '../sym_util/sym_util.gyp:sym_util',
        '../../base/base.gyp:base',
        '../../third_party/pcre/pcre.gyp:pcre',
      ],
    },
    {
      'target_name': 'test_common',
      'type': 'static_library',
      'sources': [
        'kernel_log_unittest_data.h',
        'kernel_log_unittest_data.cc',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],      
    },
    {
      'target_name': 'make_test_data',
      'type': 'executable',
      'sources': [
        'make_test_data.cc',
      ],
      'dependencies': [
        'test_common',
        '../../base/base.gyp:base',
        '../../testing/gtest.gyp:gtest',
      ],      
    },
    {
      # Our tests and Sawbuck.exe need the dbghelp and symsrv
      # DLLs in their parent directory, this copies them there.
      'target_name': 'copy_dlls',
      'type': 'none',
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)',
          'files': [
            '../../third_party/debugging_tools/files/dbghelp.dll',
            '../../third_party/debugging_tools/files/symsrv.dll',
          ],
        },
      ],
    },
    {
      'target_name': 'log_view_unittests',
      'type': 'executable',
      'sources': [
        'filtered_log_view_unittest.cc',
        'kernel_log_consumer_unittest.cc',
        'log_consumer_unittest.cc',
        'sawbuck_guids.h',
        'symbol_lookup_service_unittest.cc',
        'unittest_main.cc',
        'viewer_window_unittest.cc',
      ],
      'dependencies': [
        'copy_dlls',
        'log_view_lib',
        'test_common',
        '../../base/base.gyp:base',
        '../../testing/gmock.gyp:gmock',
        '../../testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'Sawbuck',
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
        'log_view_lib',
        'sawbuck_version',
        '../../base/base.gyp:base',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'SubSystem': 2,
          'UACExecutionLevel': 2,
        },
      },
    },
    {
      'target_name': 'test_logger',
      'type': 'executable',
      'sources': [
        'test_logger.cc',
      ],
      'dependencies': [
        '../../base/base.gyp:base',
      ],
    },
  ]
}
