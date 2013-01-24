#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.
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

"""Utility script to email a test report to one or more addresses."""

# Standard imports
#   pylint: disable=W0404
#       -> pylint gets confused by the email modules lazy importer
import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import glob
import mimetypes
import optparse
import os
import smtplib


_COMMASPACE = ', '


def ReadFile(file_path):
  """Reads the contents of a given file path.

  Args:
    file_path: The path to the file to read.

  Returns:
    The contents of the file.
  """
  with open(file_path, 'rb') as stream:
    return stream.read()


def ResolveParameter(value):
  """Resolves between a parameter value and a file redirection.

  If the given value starts with '@' then the resolved value is
  the contents of the file path given by the rest of the value.

  Args:
    value: The raws value of the parameter

  Returns:
    The raw value if undecorated, or the contents of the referenced
    file if prefixed with '@'.
  """
  if value.startswith('@'):
    value = ReadFile(value[1:])
  return value or ''


def GetAttachment(file_path):
  """Wraps the contents of a given file path into a MIME attachment object.

  Args:
    file_path: The path to the file to generate an attachment from

  Returns:
    An MIME attachment object.
  """
  file_name = os.path.basename(file_path)
  content_type, encoding = mimetypes.guess_type(file_name)
  if content_type is None or encoding is not None:
    content_type = 'application/octet-stream'
  main_type, sub_type = content_type.split('/')
  attachment = email.mime.base.MIMEBase(main_type, sub_type)
  attachment.set_payload(ReadFile(file_path))
  attachment.add_header('Content-Disposition', 'attachment', filename=file_name)
  email.encoders.encode_base64(attachment)
  return attachment


def SendMail(server, sender, recipients, subject, text, attachments,
             password, ignore_missing):
  """Sends a plain text email with optional attachments.

  Args:
    server: The address of the SMTP server
    sender: The sender's email address
    recipients: The list of recipient emails addresses
    subject: The subject of the message
    text: The body of the message
    attachments: A list of file paths to attach
    password: The (optional) password to use when authenticating to
        the smtp server.
  """
  # Create the e-mail message
  envelope = email.mime.multipart.MIMEMultipart()
  envelope['Subject'] = subject
  envelope['From'] = sender
  envelope['To'] = _COMMASPACE.join(recipients)
  envelope.preamble = ''
  for file_pattern in attachments:
    matching_paths = glob.glob(file_pattern)
    if not matching_paths and not ignore_missing:
      raise Exception('%s not found' % file_pattern)
    for file_path in matching_paths:
      envelope.attach(GetAttachment(file_path))
  message = email.mime.text.MIMEText(text.encode('utf-8'), 'plain', 'UTF-8')
  envelope.attach(message)

  # Send the e-mail message
  smtp_client = smtplib.SMTP(server)
  smtp_client.starttls()
  if password:
    smtp_client.login(sender, password)
  smtp_client.sendmail(sender, recipients, envelope.as_string())
  smtp_client.quit()


def ParseArgs():
  """Parse the command line options."""
  option_parser = optparse.OptionParser()
  option_parser.add_option(
      '--from', dest='sender', metavar='EMAIL',
      help='The sender\'s email address')
  option_parser.add_option(
      '--to', action='append', metavar='EMAIL', dest='recipients', default=[],
      help='The recipient\'s address (reapeatable)')
  option_parser.add_option(
      '--subject', metavar='TEXT|@FILE', help='The subject of the email')
  option_parser.add_option(
      '--message', metavar='TEXT|@FILE', help='The body of the message')
  option_parser.add_option(
      '--attach', metavar='FILE', action='append', dest='attachments',
      default=[], help='The path of a file to attach')
  option_parser.add_option(
      '--ignore-missing', action='store_true', default=False,
      help='No errors on attempts to attach non-existing files')
  option_parser.add_option('--server', help='The SMTP server to use')
  option_parser.add_option('--password', help='The password to use')
  options, _args = option_parser.parse_args()
  if not options.sender:
    option_parser.error('--from is required')
  if not options.recipients:
    option_parser.error('At least one --to is required')
  if not options.subject:
    option_parser.error('--subject is required')
  if not options.message:
    option_parser.error('--message is reuqired')
  if not options.server:
    option_parser.error('--server is required')
  options.subject = ResolveParameter(options.subject)
  options.message = ResolveParameter(options.message)
  return options


def main():
  """Runs the send_mail module as a command line script."""
  options = ParseArgs()
  SendMail(options.server, options.sender, options.recipients,
           options.subject, options.message, options.attachments,
           options.password, options.ignore_missing)


if __name__ == '__main__':
  main()
