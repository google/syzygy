#!python
#
# Copyright 2011 Google Inc.
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

"""TODO(rogerm): write me.
"""

__author__ = 'rogerm@google.com (Roger McFarlane)'

import chrome_repo
import reorder
import log_helper

import optparse
import os
import sys
import time

REPORT_SENDER
REPORT_RECIPIENTS = 
_logger = log_helper.GetLogger(__file__)

def ParseArgs():
  """Groks the command-line arguments."""
  option_parser = optparse.OptionParser()
  option_parser.add_option(
      '--reorder-tool', metavar='EXE', help='Path to the reordering tool')
  option_parser.add_option(
      '--reorder_num-iterations', type='int', default=1, metavar='NUM',
      help='The number of reorder iterations to run (default: %default)') 
  chrome_repo.AddCommandLineOptions(option_parser)
  report_group = optparse.OptionGroup(option_parser, 'E-Mail Reporting Options)
  report_group.add_option('--email-from', metavar='EMAIL',
                          help='The sender\'s e-mail address')
  report_group.add_option('--email-to', metavar='EMAIL', action='append', 
                          help='The recipient\'s e-mail address (reapeatable)')
  report_group.add_option('--email-password', metavar='PASSWORD',
                          help='The sender\'s email password')
  report_group.add_option('--smtp-server', metavar='HOST',
                          help='The SMTP server to use')  
  option_parser.add_option_group(report_group)
  log_helper.AddCommandLineOptions(option_parser)
  options, reorder_test_args = parser.parse_args()
  chrome_repo.ValidateCommandLineOptions(option_parser, options)
  log_helper.ValidateCommandLineOptions(option_parser, options)
  if options.email_to:
    if not options.email_from:
      option_parser.error('--email-to specified without --email-from')
    if not options.smtp_server:
      option_parser.error('--smtp-server is required to send reports')
  return options, reorder_test_args
 

def main():
  """Main script body."""
  options, test_args = ParserArgs()
  log_helper.InitLogger(options)
  logger = log_helper.GetLogger()
  message_buffer = cStringIO.StringIO()
  log_helper.AddStreamHandler(message_buffer, log_helper.VERBOSE)
  repo = chrome_repo.ChromeRepo(options.repo_url, options.repo_work_dir)
  chrome_dir = repo.DownloadBuild(options.repo_build_id)
  test_program = os.path.join(work_dir, 'automated_ui_tests.exe')
  input_bin = os.path.join(work_dir, 'chrome.dll')
  input_pdb = os.path.join(work_dir, 'chrome_dll.pdb')
  test = reorder.ReorderTest(
      options.reorder_tool, input_bin, input_pdb, test_program, test_args)
  passed, failed = test.Run(seed=options.seed, options.num_iterations)
  summary = reorder.GetSummaryLine(passed, failed)
  if options.email_to:
    send_mail.SendMail(server=options.smtp_server, sender=options.email_from,
                       recipients=options.email_to, subject=summary,
                       message=message_buffer.getvalue(),
                       attachments=WriteSummaryLine(options.summary_file, passed, failed)
  return was_successful

if __name__ == '__main__':
  if not main():
    sys.exit(1)
