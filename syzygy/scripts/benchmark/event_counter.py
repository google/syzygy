#!/usr/bin/python2.6
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
"""A utility class to process ETW logs and distill them to discrete metrics.
"""

import etw
import etw.descriptors.pagefault as pagefault
import etw.descriptors.pagefault_xp as pagefault_xp
import etw.descriptors.process as process
import etw_db
import logging
import optparse
import re


# TODO(siggi): make this configurable?
_CHROME_RE = re.compile(r'^chrome\.exe$', re.I)


# Set up a file-local logger.
_LOGGER = logging.getLogger(__name__)


class LogEventCounter(etw.EventConsumer):
  """A utility class to parse salient metrics from ETW logs."""

  def __init__(self, file_db, module_db, process_db):
    """Initialize a log event counter.

    Args:
        file_db: an etw_db.FileNameDatabase instance.
        module_db: an etw_db.ModuleDatabase instance.
        process_db: an etw_db.ProcessThreadDatabase instance.
    """
    self._file_db = file_db
    self._module_db = module_db
    self._process_db = process_db
    self._hardfaults = 0
    self._softfaults = 0
    self._process_launch = []

  @etw.EventHandler(process.Event.Start)
  def _OnProcessStart(self, event):
    if _CHROME_RE.search(event.ImageFileName):
      self._process_launch.append(event.time_stamp)

  @etw.EventHandler(pagefault.Event.HardFault)
  def _OnHardFault(self, event):
    # Resolve the thread id in the event back to the faulting process.
    process = self._process_db.GetThreadProcess(event.TThreadId)
    if process and _CHROME_RE.search(process.image_file_name):
      self._hardfaults += 1

  @etw.EventHandler(pagefault.Event.AccessViolation,
                    pagefault.Event.CopyOnWrite,
                    pagefault.Event.DemandZeroFault,
                    pagefault.Event.GuardPageFault,
                    pagefault.Event.TransitionFault)
  def _OnSoftFault(self, event):
    # Resolve the faulting process.
    process = self._process_db.GetProcess(event.process_id)
    if process and _CHROME_RE.search(process.image_file_name):
      self._softfaults += 1
