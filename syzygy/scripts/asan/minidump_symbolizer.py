#!python
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""A utility script to automate the process of symbolizing a SyzyASan
minidump.
"""

from collections import namedtuple
import optparse
import os
import re
import subprocess
import sys


# The sentinel value that we use at the end of the command executed in the
# debugger.
_SENTINEL = 'ENDENDEND'


# The default values for the path to cdb.exe.
_DEFAULT_CDB_PATHS = [
    r'c:\Program Files (x86)\Debugging Tools for Windows (x86)\cdb.exe',
    r'c:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\cdb.exe',
  ]


# The frame containing the error info structure.
_BAD_ACCESS_INFO_FRAME = 'asan_rtl!agent::asan::AsanRuntime::OnError'


# Various command that'll be run in the debugger.
_GET_BAD_ACCESS_INFO_COMMAND = 'dt error_info'
_GET_ALLOC_STACK_COMMAND = 'dps @@(&error_info->alloc_stack) ' \
                           'l@@(error_info->alloc_stack_size);'
_GET_FREE_STACK_COMMAND = 'dps @@(&error_info->free_stack) ' \
                          'l@@(error_info->free_stack_size);'


# The helper string that will be included at the beginning of the printed crash
# reports.
_ERROR_HELP_URL = 'You can go to \
https://code.google.com/p/syzygy/wiki/SyzyASanBug to get more information \
about how to treat this bug.'


# A named tuple that will contain an ASan crash report.
ASanReport = namedtuple('ASanReport', 'bad_access_info crash_stack alloc_stack '
                        'free_stack')


# Match a stack frame as printed by cdb.exe (or windbg.exe).
#
# Here's some examples of stack frames that this regex will match:
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 foo!bar+0x18
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 0xcafebabe
#
# Here's a description of the different groups in this regex:
#     - args: The arguments in front of the module name.
#     - module: The module's name.
#     - location: The location in the module.
#     - address: If the module name is not available then we'll get its address.
_STACK_FRAME_RE = re.compile("""
    ^
    (?P<args>([0-9A-F]+\ +)+)
    (?:
      (?P<module>[^ ]+)(!(?P<location>.*))? |
      (?P<address>0x[0-9a-f]+)
    )
    $
    """, re.VERBOSE | re.IGNORECASE)


# Match a list of modules as printed by cdb.exe when running the 'lm n' command.
#
# Here's a description of the different groups in this regex:
#     - start: Module's start address.
#     - end: Module's end address.
#     - module_name: Module's name.
#     - image_name: Image's name.
_MODULE_MATCH_RE = re.compile("""
    (?P<start>\w+)\s+
    (?P<end>\w+)\s+
    (?P<module_name>\w+)\s+
    (?P<image_name>.*)
    """, re.VERBOSE | re.IGNORECASE)


# Match a Chrome frame in a stack trace.
_CHROME_RE = re.compile('(chrome[_0-9A-F]+)', re.VERBOSE | re.IGNORECASE)


def _Command(debugger, command):
  """Execute a command in a debugger instance.

  Args:
    debugger: A handle to a cdb debugging session.
    command: The command to execute.

  Returns:
    The output of the debugger after running this command.
  """
  debugger.stdin.write(command + '; .echo %s\n' % _SENTINEL)
  lines = []
  while True:
    line = debugger.stdout.readline().rstrip()
    # Sometime the sentinel value is preceded by '0:000> '.
    if line.replace('0:000> ', '') == _SENTINEL:
      break
    lines.append(line)
  return lines


def NormalizeChromeSymbol(symbol):
  """Normalize a Chrome symbol."""
  return _CHROME_RE.sub('chrome_dll', symbol)


def NormalizeStackTrace(stack_trace):
  """Normalize a given stack trace.

  Args:
    stack_trace: The stack trace to normalize.

  Returns:
    The normalized stack trace.
  """
  trace_hash = 0
  output_trace = []
  for line in stack_trace:
    m = _STACK_FRAME_RE.match(line)
    if not m:
      continue
    address = m.group('address')
    module = m.group('module')
    location = m.group('location')
    if address:
      output_trace.append(address)
    else:
      module = NormalizeChromeSymbol(module)
      if location:
        location = NormalizeChromeSymbol(location)
      else:
        location = 'unknown'
      frame = '%s!%s' % (module, location)
      output_trace.append(frame)

  return output_trace


def LoadSymbols(debugger, pdb_path):
  """Loads the pdbs for the loaded modules if they are present in |pdb_path|

  Args:
    debugger: A handle to a cdb debugging session.
    command: The path containing the pdbs.
  """
  pdbs = [f for f in os.listdir(pdb_path) if f.endswith('.pdb')]
  # The path needs to be quoted to avoid including the sentinel value in cdb's
  # symbol search path.
  _Command(debugger, '.sympath \"%s\"' % pdb_path)
  for line in _Command(debugger, 'lm n'):
    m = _MODULE_MATCH_RE.match(line)
    if m is None:
      continue
    image_name =  m.group('image_name')
    if image_name is None:
      continue
    pdb_name = image_name + '.pdb'
    if pdb_name in pdbs:
      _Command(debugger, '.reload /fi %s' % image_name)

  _Command(debugger, '.symfix')


def ProcessMinidump(minidump_filename, cdb_path, pdb_path):
  """Process a minidump.

  This analyzes the error contained in the minidump and returns the crash report
  for it.

  Args:
    minidump_filename: The minidump filename.
    cdb_path: The path to cdb.exe.
    pdb_path: (Optional) The path to the pdbs for the loaded modules.

  Returns:
    The crash report to be printed.
  """
  debugger = subprocess.Popen([cdb_path,
                               '-z', minidump_filename],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
  if pdb_path is not None:
    LoadSymbols(debugger, pdb_path)

  # Enable the line number informations.
  _Command(debugger, '.lines')

  # Get the SyzyASan crash stack and try to find the frame containing the
  # bad access info structure.

  asan_crash_stack = _Command(debugger, 'kv')

  bad_access_info_frame = 0;
  for line in NormalizeStackTrace(asan_crash_stack):
    if line.find(_BAD_ACCESS_INFO_FRAME) == -1:
      bad_access_info_frame += 1
    else:
      break

  if bad_access_info_frame == -1:
    # End the debugging session.
    debugger.stdin.write('q\n')
    debugger.wait()
    print 'Unable to find the %s frame for %d.' % (_BAD_ACCESS_INFO_FRAME,
                                                   minidump_filename)
    return

  # Get the allocation, free and crash stack traces.
  _Command(debugger, '.frame %X' % bad_access_info_frame)
  bad_access_info = _Command(debugger, _GET_BAD_ACCESS_INFO_COMMAND)
  bad_access_info.pop(0)
  alloc_stack = (
      NormalizeStackTrace(_Command(debugger, _GET_ALLOC_STACK_COMMAND)))
  free_stack = NormalizeStackTrace(_Command(debugger, _GET_FREE_STACK_COMMAND))
  _Command(debugger, '.ecxr')
  crash_stack = NormalizeStackTrace(_Command(debugger, 'kv'))

  # End the debugging session.
  debugger.stdin.write('q\n')
  debugger.wait()

  report = ASanReport(bad_access_info = bad_access_info,
                      crash_stack = crash_stack,
                      alloc_stack = alloc_stack,
                      free_stack = free_stack)

  return report


def PrintASanReport(report):
  """Print a crash report.

  Args:
    report: The report to print.
  """
  print 'Bad access information:'
  for line in report.bad_access_info: print line
  print '\nCrash stack:'
  for line in report.crash_stack: print line
  if len(report.alloc_stack) != 0:
    print '\nAllocation stack:'
    for line in report.alloc_stack: print line
  if len(report.free_stack) != 0:
    print '\nFree stack:'
    for line in report.free_stack: print line
  print '\n', _ERROR_HELP_URL


_USAGE = """\
%prog [options]

Symbolizes a minidump that has been generated by SyzyASan. This prints the
crash, alloc and free stack traces and gives more information about the crash.
"""


def _ParseArguments():
  """Parse the command line arguments.

  Returns:
    The options on the command line.
  """
  parser = optparse.OptionParser(usage=_USAGE)
  # TODO(sebmarchand): Move this to an argument instead of a switch?
  parser.add_option('--minidump',
                    help='The input minidump.')
  parser.add_option('--cdb-path', help='(Optional) The path to cdb.exe.')
  parser.add_option('--pdb-path',
                    help='(Optional) The path to the folder containing the'
                         ' PDBs.')
  (opts, args) = parser.parse_args()

  if len(args):
    parser.error('Unexpected argument(s).')

  if not opts.cdb_path:
    for path in _DEFAULT_CDB_PATHS:
      if os.path.isfile(path):
        opts.cdb_path = path
        break
    if not opts.cdb_path:
      parser.error('Unable to find cdb.exe.')

  if not opts.minidump:
    parser.error('You must provide a minidump.')

  opts.minidump = os.path.abspath(opts.minidump)

  return opts


def main():
  """Parse arguments and do the symbolization."""
  opts = _ParseArguments()

  report = ProcessMinidump(opts.minidump, opts.cdb_path, opts.pdb_path)
  PrintASanReport(report)

  return 0


if __name__ == '__main__':
  sys.exit(main())
