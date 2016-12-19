# Copyright 2013 Google Inc. All Rights Reserved.
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
      'target_name': 'protect_lib',
      'type': 'static_library',
      'sources': [
        'protect_lib/code_randomizer.cc',
        'protect_lib/code_randomizer.h',
        'protect_lib/equation_gen.cc',
        'protect_lib/equation_gen.h',
        'protect_lib/integrity_check_transform.cc',
        'protect_lib/integrity_check_transform.h',
        'protect_lib/integrity_check_layout_transform.cc',
        'protect_lib/integrity_check_layout_transform.h',
        'protect_lib/protect_app.cc',
        'protect_lib/protect_app.h',
        'protect_lib/protect_flummox.cc',
        'protect_lib/protect_flummox.h',
        'protect_lib/protect_utils.cc',
        'protect_lib/protect_utils.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/application/application.gyp:application_lib',
        '<(src)/syzygy/assm/assm.gyp:assm_lib',
        '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_lib',
        '<(src)/syzygy/block_graph/transforms/block_graph_transforms.gyp:'
            'block_graph_transforms_lib',
        '<(src)/syzygy/ar/ar.gyp:ar_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/instrument/instrument.gyp:instrument_lib',
        '<(src)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_lib',
        '<(src)/syzygy/relink/relink.gyp:relink_lib',
      ],
    },
    {
      'target_name': 'protect',
      'type': 'executable',
      'sources': [
        'protect/protect.cc',
      ],
      'dependencies': [
        'protect_lib',
      ],
    },
    {
      'target_name': 'protect_unittest',
      'type': 'executable',
      'sources': [
        'protect_unittest/integrity_check_transform_unittests.cc',
        'protect_unittest/protect_app_unittests.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'protect_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:test_dll',
      ],
    },
  ],
}
