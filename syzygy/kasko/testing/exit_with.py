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

# Used to test python_util.cc. Adds its arguments and '-p' switch value and uses
# the sum as its exit code. Switches are treated differently than arguments by
# CommandLine, and proved to be tricky in the implementation. Hence this script
# permits testing both, and in combination.


import optparse
import sys

def main():
  exit_code = 0
  option_parser = optparse.OptionParser()
  option_parser.add_option('-p', type='int',
                           dest='plus',
                           help='A value to add to the exit code')

  options, args = option_parser.parse_args()

  if options.plus:
    exit_code += options.plus

  exit_code += sum([int(arg) for arg in args])

  sys.exit(exit_code)

if __name__ == '__main__':
  sys.exit(main())
