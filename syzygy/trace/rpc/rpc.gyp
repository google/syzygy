# Copyright 2012 Google Inc. All Rights Reserved.
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
    'rpc_out_dir': '<(SHARED_INTERMEDIATE_DIR)/syzygy/trace/rpc',
  },
  'target_defaults': {
    'include_dirs': [
      '<(DEPTH)',
    ],
  },
  'targets': [
    {
      # TODO(rogerm): Use midl_rpc.gypi and make this a static_library target.
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
            '<(rpc_out_dir)/call_trace_rpc.h',
            '<(rpc_out_dir)/call_trace_rpc_c.c',
            '<(rpc_out_dir)/call_trace_rpc_s.c',
          ],
          'action': [
            'midl.exe', 'call_trace_rpc.idl',
            '-nologo',
            '-char', 'signed',
            '-env', 'win32',
            '-Oicf',
            '-prefix', 'all', 'CallTraceClient_', 'server', 'CallTraceService_',
            '-out', '<(rpc_out_dir)',
            '-h', 'call_trace_rpc.h',
          ]
        }
      ],
    },
    {
      # TODO(rogerm): Drop the IDL generated files and invert the dependency
      #     on call_trace_rpc_idl when it is updated to use midl_rpc.gypi.
      'target_name': 'rpc_common_lib',
      'product_name': 'rpc_common',
      'type': 'static_library',
      'dependencies': [
        'call_trace_rpc_idl',
        '<(DEPTH)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
      ],
      'sources': [
        '<(rpc_out_dir)/call_trace_rpc.h',
        '<(rpc_out_dir)/call_trace_rpc_c.c',
        '<(rpc_out_dir)/call_trace_rpc_s.c',
        'rpc_helpers.cc',
        'rpc_helpers.h',
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
      'target_name': 'logger_rpc',
      'type': 'static_library',
      # Build our IDL file to the shared intermediate directory using the
      # midl_rpc.gypi include (because the default rules for .idl files are
      # specific to COM interfaces). This include expects the prefix and
      # midl_out_dir variables to be defined.
      'variables': {
        'prefix': 'Logger',
        'midl_out_dir': '<(SHARED_INTERMEDIATE_DIR)/syzygy/trace/rpc',
      },
      'includes': ['../../build/midl_rpc.gypi'],
      'sources': ['logger_rpc.idl'],
      'all_dependent_settings': {
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
      },
      'dependencies': ['rpc_common_lib'],
    },
  ],
}
