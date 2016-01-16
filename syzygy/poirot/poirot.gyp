# Copyright 2015 Google Inc. All Rights Reserved.
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
  'targets': [
    {
      'target_name': 'poirot',
      'type': 'executable',
      'sources': [
        'poirot_main.cc',
      ],
      # TODO(sebmarchand): Fix the dependency inheritance from the crashdata
      # proto library.
      'include_dirs': ['<(SHARED_INTERMEDIATE_DIR)'],
      'dependencies': [
        'poirot_lib',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
    },
    {
      'target_name': 'poirot_lib',
      'type': 'static_library',
      'sources': [
        'minidump_processor.cc',
        'minidump_processor.h',
        'poirot_app.cc',
        'poirot_app.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/application/application.gyp:application_lib',
        '<(src)/syzygy/crashdata/crashdata.gyp:crashdata_lib',
        '<(src)/syzygy/minidump/minidump.gyp:minidump_lib',
        '<(src)/third_party/protobuf/protobuf.gyp:protobuf_lite_lib',
      ],
      'export_dependent_settings': [
        '<(src)/syzygy/crashdata/crashdata.gyp:crashdata_lib',
      ],
    },
    {
      'target_name': 'poirot_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
    },
    {
      'target_name': 'poirot_unittests',
      'type': 'executable',
      'sources': [
        'poirot_app_unittest.cc',
        'minidump_processor_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'poirot_lib',
        'poirot_unittest_utils',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/common/common.gyp:common_unittest_utils',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ]
}
