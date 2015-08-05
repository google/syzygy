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
"""Utility for creating a copy of an example that is LargeAddressAware."""

import logging
import optparse
import os
import struct
import subprocess
import sys


_LOGGER = logging.getLogger(os.path.basename(__file__))


def _ParseCommandLine():
  option_parser = optparse.OptionParser()
  option_parser.add_option('--input', type='string',
      help='The input file to be copied.')
  option_parser.add_option('--output', type='string',
      help='The output file to be written.')
  option_parser.add_option('--force', action='store_true', default=False,
      help='Forces writing an existing output file even if the contents would '
           'be the same.')
  option_parser.add_option('--overwrite', action='store_true', default=False,
      help='Enables overwriting existing output files.')
  option_parser.add_option('--verbose', dest='log_level', action='store_const',
      default=logging.INFO, const=logging.DEBUG,
      help='Enables verbose logging.')
  option_parser.add_option('--quiet', dest='log_level', action='store_const',
      default=logging.INFO, const=logging.ERROR,
      help='Disables all output except for errors.')

  options, args = option_parser.parse_args()

  # Configure logging.
  logging.basicConfig(level=options.log_level)

  # Validation.
  if not options.input:
    option_parser.error('Must specify --input.')
  if not os.path.exists(options.input):
    option_parser.error('Input file does not exist: %s' % options.input)
  if not options.output:
    option_parser.error('Must specify --output.')
  if os.path.exists(options.output):
    input = os.path.normpath(os.path.abspath(options.input))
    output = os.path.normpath(os.path.abspath(options.output))
    if input == output:
      option_parser.error('Input and output must not refer to the same file.')

  return options, args


def _Shell(*cmd, **kw):
  """Runs |cmd|, returns the results from Popen(cmd).communicate(). Additional
  keyword arguments are passed on to subprocess.Popen. If |stdout| and |stderr|
  are not specified, they default to subprocess.PIPE.
  """
  if 'cwd' in kw:
    _LOGGER.debug('Executing %s in "%s".', cmd, kw['cwd'])
  else:
    _LOGGER.debug('Executing %s.', cmd)

  kw['shell'] = True
  kw.setdefault('stdout', subprocess.PIPE)
  kw.setdefault('stderr', subprocess.PIPE)
  prog = subprocess.Popen(cmd, **kw)

  stdout, stderr = prog.communicate()
  if prog.returncode != 0:
    raise RuntimeError('Command "%s" returned %d.' % (cmd, prog.returncode))
  return (stdout, stderr)


# These hardcoded offsets are directly extracted from the IMAGE_DOS_HEADER
# and IMAGE_NT_HEADERS definitions.
_OFFSET_E_LFANEW = 0x3C
_OFFSET_CHARACTERISTICS = 0x16
_LAA_BIT = 0x0020


def _GetCharacteristicsOffset(image):
  i = _OFFSET_E_LFANEW
  e_lfanew = struct.unpack('<I', image[i:i + 4])[0]

  return e_lfanew + _OFFSET_CHARACTERISTICS


def _IsLaa(image):
  i = _GetCharacteristicsOffset(image)
  characteristics = struct.unpack('<H', image[i:i + 2])[0]
  return (characteristics & _LAA_BIT) == _LAA_BIT


def _MakeLaa(image):
  i = _GetCharacteristicsOffset(image)
  characteristics = struct.unpack('<H', image[i:i + 2])[0]
  characteristics |= _LAA_BIT
  return image[0:i] + struct.pack('<H', characteristics) + image[i + 2:]


def _NeedWrite(options, data):
  if options.force:
    _LOGGER.debug('Forcing write of output file.')
    return True
  if not os.path.exists(options.output):
    return True
  if os.path.getmtime(options.output) < os.path.getmtime(options.input):
    return True
  output_data = open(options.output, 'rb').read()
  if data != output_data:
    return True
  _LOGGER.info('Output file up to date.')
  return False


def _ErrorExit(msg):
  _LOGGER.error(msg)
  sys.exit(1)


def main():
  options, args_unused = _ParseCommandLine()

  data = open(options.input, 'rb').read()

  # Determine if the input binary is already large address aware.
  if _IsLaa(data):
    _ErrorExit('Input binary is already Large Address Aware.')

  # Make the file LAA and write it if need be.
  data = _MakeLaa(data)
  if _NeedWrite(options, data):
    if os.path.exists(options.output) and not options.overwrite:
      _ErrorExit('Output file already exists. Is --overwrite intended?')
    with open(options.output, 'wb') as f:
      _LOGGER.info('Writing file: %s', options.output)
      f.write(data)

  sys.exit(0)


if __name__ == '__main__':
  main()
