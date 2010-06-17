#!python
# Copyright 2010 Google Inc.
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
from etw import TraceConsumer
import os
import unittest


_SRC_DIR = os.path.abspath(os.path.join(__file__, '../../../../..'))

class TraceConsumerTest(unittest.TestCase):
  _TEST_LOG = os.path.normpath(
      os.path.join(_SRC_DIR,
                   'sawbuck/log_lib/test_data/image_data_64_v2.etl'))

  def testCreateConsumer(self):
    consumer = TraceConsumer()

  def testOpenFileSession(self):
    consumer = TraceConsumer()
    consumer.OpenFileSession(self._TEST_LOG)

  def testConsume(self):
    class TestConsumer(TraceConsumer):
      def __init__(self):
        super(TestConsumer, self).__init__()
        self._events = 0

      def ProcessEvent(self, event):
        self._events = self._events + 1

    consumer = TestConsumer()
    consumer.OpenFileSession(self._TEST_LOG)
    consumer.Consume()
    self.assertNotEqual(0, consumer._events)

if __name__ == '__main__':
  unittest.main()
