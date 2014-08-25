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
#
# GYP include file for common settings used across the various protobuf
# libraries.

{
  # These settings are passed on to users of protobuf libraries, ensuring that
  # they compile cleanly.
  'direct_dependent_settings': {
    'include_dirs': [ '.', 'src', ],
    'defines': [
      'GOOGLE_PROTOBUF_NO_RTTI',
      'GOOGLE_PROTOBUF_NO_STATIC_INITIALIZER',
    ],
  },
}
