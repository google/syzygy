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
#
# Files that need to be distributed as part of our official release need
# to be added to this file so that they will be included in the
# kasko.zip and kasko_symbols.zip archives created and archived by our official
# builder.

{
  'variables': {
    'lib_dir': '<(PRODUCT_DIR)',

    'binaries': [
      '<(PRODUCT_DIR)/kasko.dll',
      '<(lib_dir)/kasko.dll.lib',
    ],

    'headers': [
      # These must all start with '<(src)' in order to be archived in the
      # correct relative path.
      '<(src)/syzygy/kasko/api/client.h',
      '<(src)/syzygy/kasko/api/crash_key.h',
      '<(src)/syzygy/kasko/api/kasko_export.h',
      '<(src)/syzygy/kasko/api/minidump_type.h',
      '<(src)/syzygy/kasko/api/reporter.h',
    ],

    'symbols': [
      '<(PRODUCT_DIR)/kasko.dll.pdb',
    ],
  }
}
