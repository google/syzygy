# Copyright 2015 Google Inc. All Rights Reserved.
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
  },
  'targets': [
    {
      'target_name': 'refinery_proto',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'actions': [
        {
          'action_name': 'compile_refinery_proto',
          'inputs': [
            'refinery.proto',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/'
                'refinery/process_state/refinery.pb.cc',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/'
                'refinery/process_state/refinery.pb.h',
          ],
          'action': [
            '<(PRODUCT_DIR)/protoc.exe',
            '--proto_path=<(src)/syzygy/refinery/process_state',
            '--cpp_out=<(SHARED_INTERMEDIATE_DIR)/syzygy/'
                'refinery/process_state',
            '<(src)/syzygy/refinery/process_state/refinery.proto',
          ],
          'process_outputs_as_sources': 1,
        },
      ],
      'dependencies': [
        '<(src)/third_party/protobuf/protobuf.gyp:protoc',
      ],
      'all_dependent_settings': {
        # This dependency allows bringing in the generated protobuf files.
        'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
        # Disable warnings arising from protobuf generated code.
        'msvs_disabled_warnings': [
          '4018',  # signed/unsigned mismatch.
          '4125',  # decimal digit terminates octal escape sequence.
        ],
        # This target exports a hard dependency because it generates header
        # files.
        'hard_dependency': 1,
      },
    },
    {
      'target_name': 'process_state_lib',
      'type': 'static_library',
      'sources': [
        'layer_data.cc',
        'layer_data.h',
        'layer_traits.h',
        'process_state.cc',
        'process_state.h',
        'process_state_util.cc',
        'process_state_util.h',
        'record_traits.h',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/'
            'refinery/process_state/refinery.pb.cc',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/'
            'refinery/process_state/refinery.pb.h',
      ],
      'dependencies': [
        'refinery_proto',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
        '<(src)/syzygy/refinery/types/types.gyp:types_lib',
        '<(src)/third_party/protobuf/protobuf.gyp:protobuf_lib',
      ],
      'export_dependent_settings': [
        'refinery_proto',
        '<(src)/third_party/protobuf/protobuf.gyp:protobuf_lib',
      ]
    },
  ],
}
