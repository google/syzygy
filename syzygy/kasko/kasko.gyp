# Copyright 2014 Google Inc. All Rights Reserved.
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
    'files_to_archive': [
      '<(PRODUCT_DIR)/kasko.zip',
      '<(PRODUCT_DIR)/kasko_symbols.zip',
    ],
  },
  'includes': [
    'archive_contents.gypi',
    'unittests.gypi',
  ],
  'targets': [
    {
      'target_name': 'kasko_version',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'version.h.template',
      ],
      'actions': [
        {
          'action_name': 'make_version_gen',
          'inputs': [
            '<(src)/syzygy/build/template_replace.py',
            '<(src)/syzygy/kasko/VERSION',
            '<(src)/syzygy/build/LASTCHANGE.gen',
            'version.h.template',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/kasko/version.h',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/template_replace.py',
            '--input', 'version.h.template',
            '--output', '<(SHARED_INTERMEDIATE_DIR)/syzygy/kasko/version.h',
            '<(src)/syzygy/kasko/VERSION',
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
      'target_name': 'kasko_rpc',
      'type': 'static_library',
      'variables': {
        'prefix': 'Kasko',
        'midl_out_dir': '<(SHARED_INTERMEDIATE_DIR)/syzygy/kasko',
      },
      # This path must be relative.
      'includes': ['../build/midl_rpc.gypi'],
      'sources': ['kasko_rpc.idl'],
      'all_dependent_settings': {
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
        'msvs_settings': {
          'VCLinkerTool': {
            'AdditionalDependencies': [
              # SDK import libs.
              'rpcrt4.lib',
            ],
          },
        },
      },
    },
    {
      'target_name': 'kasko_lib',
      'type': 'static_library',
      'sources': [
        'client.cc',
        'client.h',
        'crash_keys_serialization.cc',
        'crash_keys_serialization.h',
        'dll_lifetime.cc',
        'dll_lifetime.h',
        'http_agent.h',
        'http_agent_impl.cc',
        'http_agent_impl.h',
        'http_response.h',
        'internet_helpers.cc',
        'internet_helpers.h',
        'minidump.cc',
        'minidump.h',
        'report_repository.cc',
        'report_repository.h',
        'reporter.cc',
        'reporter.h',
        'service.h',
        'service_bridge.cc',
        'service_bridge.h',
        'upload.cc',
        'upload.h',
        'upload_thread.cc',
        'upload_thread.h',
        'user_agent.cc',
        'user_agent.h',
        'waitable_timer.h',
        'waitable_timer_impl.cc',
        'waitable_timer_impl.h',
      ],
      'all_dependent_settings': {
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
        'msvs_settings': {
          'VCLinkerTool': {
            'AdditionalDependencies': [
              # SDK import libs.
              'dbghelp.lib',
              'rpcrt4.lib',
              'Winhttp.lib',
            ],
          },
        },
      },
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/common/rpc/rpc.gyp:common_rpc_lib',
        'kasko_version',
        'kasko_rpc',
      ],
      'defines': [
        'KASKO_IMPLEMENTATION',
      ],
    },
    {
      'target_name': 'kasko',
      'type': 'loadable_module',
      'sources': [
        'api/client.cc',
        'api/client.h',
        'api/kasko_dll.cc',
        'api/kasko_export.h',
        'api/reporter.cc',
        'api/reporter.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        'kasko_lib'
      ],
      'defines': [
        'KASKO_IMPLEMENTATION',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Link against the XP-constrained user32 import libraries for
          # kernel32 and user32 of the platform-SDK provided one to avoid
          # inadvertently taking dependencies on post-XP user32 exports.
          'IgnoreDefaultLibraryNames': [
            'user32.lib',
            'kernel32.lib',
          ],
          'AdditionalDependencies': [
            # Custom import libs.
            'user32.winxp.lib',
            'kernel32.winxp.lib',
          ],
          'AdditionalLibraryDirectories': [
            '<(src)/build/win/importlibs/x86',
            '<(src)/syzygy/build/importlibs/x86',
          ],
          # This module should delay load nothing.
          'DelayLoadDLLs=': [
          ],
          # Force MSVS to produce the same output name as Ninja.
          'ImportLibrary': '$(OutDir)lib\$(TargetFileName).lib'
        },
      },
    },
    {
      'target_name': 'test_support_kasko',
      'type': 'static_library',
      'sources': [
        'internet_unittest_helpers.cc',
        'internet_unittest_helpers.h',
        'testing/minidump_unittest_helpers.cc',
        'testing/minidump_unittest_helpers.h',
        'testing/mock_service.cc',
        'testing/mock_service.h',
        'testing/test_server.cc',
        'testing/test_server.h',
        'testing/upload_observer.cc',
        'testing/upload_observer.h',
      ],
      'dependencies': [
        'kasko_lib',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
       ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
          'AdditionalDependencies': [
            # SDK import libs.
            'dbgeng.lib',
          ],
        },
      },
    },
    {
      'target_name': 'kasko_unittests',
      'type': 'executable',
      'sources': [
        '<(src)/base/test/run_all_unittests.cc',
        'client_unittest.cc',
        'crash_keys_serialization_unittest.cc',
        'http_agent_impl_unittest.cc',
        'internet_helpers_unittest.cc',
        'minidump_unittest.cc',
        'report_repository_unittest.cc',
        'reporter_unittest.cc',
        'service_bridge_unittest.cc',
        'upload_thread_unittest.cc',
        'upload_unittest.cc',
        'user_agent_unittest.cc',
        'waitable_timer_impl_unittest.cc',
      ],
      'dependencies': [
        'kasko_lib',
        'test_support_kasko',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
       ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
          'AdditionalDependencies': [
            # SDK import libs.
            'dbgeng.lib',
          ],
        },
      },
    },
    {
      'target_name': 'kasko_api_tests',
      'type': 'executable',
      'sources': [
        '<(src)/base/test/run_all_unittests.cc',
        'api/api_tests.cc',
      ],
      'dependencies': [
        'kasko',
        'test_support_kasko',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
       ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
          'AdditionalDependencies': [
            # SDK import libs.
            'dbgeng.lib',
          ],
          'conditions': [
            ['"<(GENERATOR)"=="ninja" or "<(GENERATOR)"=="msvs-ninja"', {
              'AdditionalDependencies': [
                '<(PRODUCT_DIR)/kasko.dll.lib',
              ],
            }],
            ['"<(GENERATOR)"=="msvs"', {
              'AdditionalDependencies': [
                '<(PRODUCT_DIR)/lib/kasko.dll.lib',
              ],
            }],
          ],


        },
      },
    },
    {
      'target_name': 'official_kasko_build',
      'type': 'none',
      'dependencies': [
        'kasko',
        '<@(unittests)',
        'archive_kasko_build_artifacts',
      ],
    },
    {
      'target_name': 'archive_kasko_build_artifacts',
      'type': 'none',
      'dependencies': [
        'kasko_binaries_zip',
      ],
      'copies': [{
        'destination': '<(PRODUCT_DIR)/archive',
        'files': ['<@(files_to_archive)'],
      }],
    },
    {
      'target_name': 'kasko_binaries_zip',
      'type': 'none',
      'dependencies': [
        'kasko',
      ],
      'actions': [
        {
          'action_name': 'create_kasko_symbols_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(src)/syzygy/build/create_zip.py',
            '<@(symbols)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/kasko_symbols.zip',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/kasko_symbols.zip',
            '--files',
            '<@(symbols)',
          ],
        },
        {
          'action_name': 'create_kasko_zip',
          'msvs_cygwin_shell': 0,
          'inputs': [
            '<(src)/syzygy/build/create_zip.py',
            '<(src)/syzygy/build/LICENSE.TXT',
            '<@(binaries)',
            '<@(headers)',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/kasko.zip',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/build/create_zip.py',
            '--output',
            '<(PRODUCT_DIR)/kasko.zip',
            '--files',
            '<(src)/syzygy/build/LICENSE.TXT',
            '<@(binaries)',
            '--subtree',
            'include',
            '<(src)',
            '<@(headers)',
          ],
        },
      ],
    },
  ],
}
