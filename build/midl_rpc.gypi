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
#
# This include file defines a rule for compiling .idl files containing
# RPC interfaces. Include it in any target that has one or more RPC .idl
# sources.
#
# To use this include, define the following variables in your target.
#
#     midl_out_dir: The path where you wish the generated stubs and headers
#         to be placed. Typically this will be something like:
#             <(SHARED_INTERMEDIATE_DIR)/path/to/files/in/main/tree
#
#     prefix: The common prefix to be assigned to the client and server
#         generated stubs. For example, setting prefix to 'Foo' will yield
#         FooClient_Function and FooServer_Function declarations and stubs
#         for each IDL generated interface member Function.
#
# Typically, your target would then add <(SHARED_INTERMEDIATE_DIR) to
# 'all_dependent_settings' : {'include_dirs' : []}.
#
# For example:
#    {
#      'target_name': 'foo_rpc',
#      'type': 'static_library',
#      'variables': {
#        'prefix': 'Foo',
#        'midl_out_dir': '<(SHARED_INTERMEDIATE_DIR)/syzygy/foo',
#      },
#      'includes': ['../../build/midl_rpc.gypi'],
#      'sources': ['foo_rpc.idl'],
#      'all_dependent_settings': {
#        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
#      },
#    },

{
  'rules': [
    {
      'rule_name': 'RPC_MIDL',
      'msvs_cygwin_shell': 0,
      'extension': 'idl',
      'inputs': [],
      'outputs': [
        '<(midl_out_dir)/<(RULE_INPUT_ROOT).h',
        '<(midl_out_dir)/<(RULE_INPUT_ROOT)_c.c',
        '<(midl_out_dir)/<(RULE_INPUT_ROOT)_s.c',
      ],
      'action': [
        'midl.exe', '<(RULE_INPUT_PATH)',
            '/nologo',
            '/char', 'signed',
            '/env', 'win32',
            '/Oicf',
            '/prefix', 'all', '<(prefix)Client_',
            '/prefix', 'server', '<(prefix)Server_',
            '/robust',
            '/h', '<(RULE_INPUT_ROOT).h',
            '/out', '<(midl_out_dir)',
      ],
      'process_outputs_as_sources': 1,
      'message': '<(RULE_INPUT_NAME)',
    },
  ],
}
