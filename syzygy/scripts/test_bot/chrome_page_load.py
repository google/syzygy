#!python
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Script for launching Chrome, having it load a set of pages, and then cleanly
shutting it down.
"""

# Standard modules.
import json
import optparse
import os
import sys

# Local modules.
import log_helper

# Modules from other locations in the repo.
_CUR_DIR = os.path.abspath(os.path.dirname(__file__))
_BENCHMARK_DIR = os.path.abspath(os.path.join(_CUR_DIR, '..', 'benchmark'))
_ETW_DB_DIR = os.path.abspath(os.path.join(_CUR_DIR, '..', '..', 'py',
                                           'etw_db'))
_ETW_DIR = os.path.abspath(os.path.join(_CUR_DIR, '..', '..', '..',
                                        'third_party', 'sawbuck', 'py', 'etw'))
sys.path.append(_BENCHMARK_DIR)
sys.path.append(_ETW_DB_DIR)
sys.path.append(_ETW_DIR)
import chrome_control
import runner


_LOGGER = log_helper.GetLogger(__file__)


def _ParseArgs():
  """Parses the command-line."""
  parser = optparse.OptionParser(
      'Usage: %prog [options] [url1 [url2 [ ... ]]]')
  parser.add_option('--chrome-dir', help='Location of Chrome installation.')
  parser.add_option('--iterations', default=1, type='int',
                    help='Number of iterations.')
  parser.add_option('--url-list', help='File with list of URLs to be opened.')
  opts, args = parser.parse_args()
  if not opts.chrome_dir:
    parser.error("Must specify --chrome-dir.")
  return (opts, args)


def _GetUrlList(opts, args):
  """Gets the list of URLs to be loaded."""
  urls = args
  if opts.url_list:
    _LOGGER.info('Loading list of URLs from \"%s\".', opts.url_list)
    urls += open(opts.url_list, 'rb').readlines()
  return urls


def main():
  if sys.platform == 'win32':
    # Don't show error dialog boxes on crashes or debug-breaks. This setting
    # is inherited by child processes, so a crash won't block automated tests.
    import ctypes
    ctypes.windll.kernel32.SetErrorMode(3)

  opts, args = _ParseArgs()

  # Get the list of URLs and determine the startup type.
  urls = _GetUrlList(opts, args)
  startup_type = chrome_control.STARTUP_NEW_TAB_PAGE
  if urls:
    startup_type = chrome_control.STARTUP_RESTORE_SESSION

  # Configure and launch the Chrome runner.
  chrome_exe = os.path.abspath(os.path.join(opts.chrome_dir, 'chrome.exe'))
  if not os.path.exists(chrome_exe):
    raise Exception('File not found: %s' % chrome_exe)
  chrome = runner.ChromeRunner(chrome_exe, None, True)
  chrome.ConfigureStartup(startup_type, urls)
  chrome.Run(opts.iterations)
  return 0


if __name__ == '__main__':
  sys.exit(main())
