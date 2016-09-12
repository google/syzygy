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
#         FooClient_Function and FooService_Function declarations and stubs
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
#      # This path must be relative.
#      'includes': ['../build/midl_rpc.gypi'],
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
            '/Oicf',
            '/prefix', 'all', '<(prefix)Client_',
            '/prefix', 'server', '<(prefix)Service_',
            '/robust',
            '/h', '<(RULE_INPUT_ROOT).h',
            '/out', '<(midl_out_dir)',
      ],
      'conditions': [
        ['target_arch == "x64"', {
          'action': [ '/env', 'amd64' ]
        }, {
          'action': [ '/env', 'win32' ]
        }],
      ],
      # This causes the output files to automatically be compiled into object
      # code included in the current target.
      'process_outputs_as_sources': 1,
      'message': '<(RULE_INPUT_NAME)',
    },
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
  # This target exports a hard dependency because it generates header files.
  'hard_dependency': 1,
}
