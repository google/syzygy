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
  },
  'targets': [
    {
      'target_name': 'crashdata_proto',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'actions': [
        {
          'action_name': 'compile_crashdata_proto',
          'inputs': [
            'crashdata.proto',
          ],
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/crashdata/crashdata.pb.cc',
            '<(SHARED_INTERMEDIATE_DIR)/syzygy/crashdata/crashdata.pb.h',
          ],
          'action': [
            '<(PRODUCT_DIR)/protoc.exe',
            '--proto_path=<(src)/syzygy/crashdata',
            '--cpp_out=<(SHARED_INTERMEDIATE_DIR)/syzygy/crashdata',
            '<(src)/syzygy/crashdata/crashdata.proto',
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
        ],
        # This target exports a hard dependency because it generates header
        # files.
        'hard_dependency': 1,
      },
    },
    {
      'target_name': 'crashdata_lib',
      'type': 'static_library',
      'sources': [
        'crashdata.cc',
        'crashdata.h',
        'json.cc',
        'json.h',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/crashdata/crashdata.pb.cc',
        '<(SHARED_INTERMEDIATE_DIR)/syzygy/crashdata/crashdata.pb.h',
      ],
      'dependencies': [
        'crashdata_proto',
        '<(src)/third_party/protobuf/protobuf.gyp:protobuf_lite_lib',
      ],
      # Disable warnings arising from protobuf generated code.
      'conditions': [
        ['target_arch=="x64"', {
          'msvs_disabled_warnings': [
            '4267',
          ],
        }],
      ],
      'export_dependent_settings': [
        '<(src)/third_party/protobuf/protobuf.gyp:protobuf_lite_lib',
      ],
    },
    {
      'target_name': 'crashdata_unittests',
      'type': 'executable',
      'sources': [
        '<(src)/syzygy/testing/run_all_unittests.cc',
        'crashdata_unittest.cc',
        'json_unittest.cc',
      ],
      'dependencies': [
        'crashdata_lib',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
