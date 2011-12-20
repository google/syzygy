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
    ],
  },
  'targets': [
    {
      # Builds our IDL file to the shared intermediate directory.
      # We invoke midl explicitly, because the rules for .idl files are
      # specific to COM interfaces, which causes RPC interfaces to always
      # be out of date.
      'target_name': 'call_trace_rpc_idl',
      'type': 'none',
      'sources': [
        'call_trace_rpc.idl',
      ],
      # Add the output dir for those who depend on us.
      'all_dependent_settings': {
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
      },
      'actions': [
        {
        'action_name': 'Compile IDL',
        'msvs_cygwin_shell': 0,
        'inputs': [
          'call_trace_rpc.idl',
        ],
        'outputs': [
          '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc.h',
          '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc_c.c',
          '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc_s.c',
        ],
        'action': [
          'midl.exe', 'call_trace_rpc.idl',
          '-nologo',
          '-char', 'signed',
          '-env', 'win32',
          '-Oicf',
          '-prefix', 'all', 'CallTraceClient_', 'server', 'CallTraceService_',
          '-out', '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace',
          '-h', 'call_trace_rpc.h',
        ]
        }
      ],
    },
    {
      'target_name': 'call_trace_common_lib',
      'product_name': 'call_trace_common',
      'type': 'static_library',
      'dependencies': [
        'call_trace_rpc_idl',
      ],
      'sources': [
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc.h',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc_c.c',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/call_trace/call_trace_rpc_s.c',
        'call_trace_control.cc',
        'call_trace_control.h',
        'call_trace_defs.cc',
        'call_trace_defs.h',
        'client_utils.cc',
        'client_utils.h',
        'rpc_helpers.cc',
        'rpc_helpers.h',
        'rpc_session.cc',
        'rpc_session.h',
        'rpc_mem.cc',
      ],
      'all_dependent_settings': {
        'msvs_settings': {
          'VCLinkerTool': {
            # GYP has a bug or misfeature whereby a library dependency used
            # from another GYP file in a different directory picks up the path
            # to that directory, so instead of using 'library', we specify the
            # library dependency here.
            'AdditionalDependencies': [
              'rpcrt4.lib',
            ],
          },
        },
      },
    },
    {
      'target_name': 'call_trace_parser_lib',
      'product_name': 'call_trace_parser',
      'type': 'static_library',
      'sources': [
        'parse_engine.cc',
        'parse_engine.h',
        'parse_engine_etw.cc',
        'parse_engine_etw.h',
        'parse_engine_rpc.cc',
        'parse_engine_rpc.h',
        'parser.h',
        'parser.cc',
      ],
      'dependencies': [
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        'call_trace_common_lib',
      ],
    },
    {
      'target_name': 'call_trace_client_rpc',
      'product_name': 'call_trace_client',
      'type': 'shared_library',
      'sources': [
        'client_rpc.cc',
        'client_rpc.def',
        'client_rpc.h',
        'client_rpc.rc',
      ],
      'dependencies': [
        'call_trace_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],
    },
    {
      'target_name': 'call_trace_client_etw',
      'product_name': 'call_trace',
      'type': 'shared_library',
      'sources': [
        'client_etw.cc',
        'client_etw.def',
        'client_etw.h',
        'client_etw.rc',
      ],
      'dependencies': [
        'call_trace_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],
    },
    {
      'target_name': 'call_trace_service_lib',
      'type': 'static_library',
      'sources': [
        'buffer_pool.cc',
        'buffer_pool.h',
        'process_info.cc',
        'process_info.h',
        'service.cc',
        'service.h',
        'service_rpc_impl.cc',
        'session.cc',
        'session.h',
      ],
      'dependencies': [
        'call_trace_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],
      'all_dependent_settings': {
        'libraries': [
          'advapi32.lib',
        ],
      },
    },
    {
      'target_name': 'call_trace_service_exe',
      'product_name': 'call_trace_service',
      'type': 'executable',
      'sources': [
        'service_main.cc',
        'service.rc',
      ],
      'dependencies': [
        'call_trace_service_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/syzygy/common/common.gyp:common_lib',
      ],
    },
    {
      'target_name': 'call_trace_unittests',
      'type': 'executable',
      'sources': [
        'parse_engine_etw_unittests.cc',
        'parse_engine_rpc_unittests.cc',
        'parse_engine_unittests.cc',
        'process_info_unittests.cc',
        'profiler_unittests.cc',
        'shadow_stack_unittests.cc',
        'service_unittests.cc',
        'unittests_main.cc',
      ],
      'dependencies': [
        'call_trace_client_etw',
        'call_trace_client_rpc',
        'call_trace_parser_lib',
        'call_trace_service_lib',
        'profile_client',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
        '<(DEPTH)/syzygy/pe/pe.gyp:pe_lib',
        '<(DEPTH)/testing/gtest.gyp:gtest',
        '<(DEPTH)/testing/gmock.gyp:gmock',
        '../pe/pe.gyp:pe_unittest_utils',
      ],
      'libraries': [
        'imagehlp.lib',
      ],
    },
    {
      'target_name': 'call_trace_control',
      'type': 'executable',
      'sources': [
        'call_trace_control_main.cc',
        'call_trace_control.rc',
      ],
      'dependencies': [
        'call_trace_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/common/common.gyp:common',
      ],
    },
    {
      'target_name': 'profile_client',
      'type': 'shared_library',
      'sources': [
        'profiler.cc',
        'profiler.def',
        'profiler.h',
        'profiler.rc',
      ],
      'dependencies': [
        'call_trace_common_lib',
        '<(DEPTH)/base/base.gyp:base',
        '<(DEPTH)/sawbuck/log_lib/log_lib.gyp:log_lib',
      ],
    },
  ],
}
