#!python
# Copyright 2012 Google Inc.
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

import httplib
import json
from handler import client
from model import client as client_db
from model import metric as metric_db
from model import product as product_db
from test.handler import handler_test

class ClientTest(handler_test.TestCase):

  def setUp(self):
    super(ClientTest, self).setUp()

    # Insert values into the db.
    p1 = product_db.Product(key_name='p1')
    p1.put()

    c1 = client_db.Client(key_name='c1', parent=p1, description='c1_desc')
    c1.put()
    c2 = client_db.Client(key_name='c2', parent=p1, description='c2_desc')
    c2.put()

    m1 = metric_db.Metric(key_name='m1', parent=c1, description='m1_desc',
                          units='stones')
    m1.put()
    m2 = metric_db.Metric(key_name='m2', parent=c1, description='m2_desc',
                          units='furlongs')
    m2.put()

  def _InitHandler(self, input):
    self._handler = client.ClientHandler()
    super(ClientTest, self)._InitHandler(self._handler, input)

  def testGetAll(self):
    self._InitHandler('')
    self._handler.get('p1', '')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'clients': [
            {'client_id': 'c1',
             'description': 'c1_desc'},
            {'client_id': 'c2',
             'description': 'c2_desc'}
        ]},
        result)

  def testGetById(self):
    self._InitHandler('')
    self._handler.get('p1', 'c1')
    self.assertEqual(httplib.OK, self._response.status)

    result = json.loads(self._response.out.getvalue())
    self.assertEqual(
        {'product_id': 'p1',
         'client_id': 'c1',
         'description': 'c1_desc',
         'metric_ids': ['m1', 'm2']},
        result)

  def testGetArgValidation(self):
    # Non-existing product ID.
    self._InitHandler('')
    self._handler.get('p2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('')
    self._handler.get('p1', 'c3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testPost(self):
    self._InitHandler('client_id=c3&description=c3_desc')
    self._handler.post('p1', '')
    self.assertEqual(httplib.CREATED, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c3 = client_db.Client.get_by_key_name('c3', p1)
    self.assertTrue(c3 is not None)
    self.assertEqual('c3_desc', c3.description)

  def testPostArgValidation(self):
    # Client ID in URL.
    self._InitHandler('client_id=c3&description=c3_desc')
    self._handler.post('p1', 'c3')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Client ID missing from body.
    self._InitHandler('description=c3_desc')
    self._handler.post('p1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Description missing from body.
    self._InitHandler('client_id=c3')
    self._handler.post('p1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('client_id=c3&description=c3_desc')
    self._handler.post('p2', '')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Existing client ID.
    self._InitHandler('client_id=c1&description=c1_desc')
    self._handler.post('p1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

  def testPut(self):
    self._InitHandler('description=new_c1_desc')
    self._handler.put('p1', 'c1')
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    c1 = client_db.Client.get_by_key_name('c1', p1)
    self.assertEqual('new_c1_desc', c1.description)

  def testPutArgValidation(self):
    # Client ID missing from URL.
    self._InitHandler('description=new_c1_desc')
    self._handler.post('p1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Description missing from body.
    self._InitHandler('')
    self._handler.post('p1', 'c1')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('description=new_c1_desc')
    self._handler.put('p2', 'c1')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('description=new_c3_desc')
    self._handler.put('p1', 'c3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

  def testDelete(self):
    self._InitHandler('')
    self._handler.delete('p1', 'c2')
    self.assertEqual(httplib.OK, self._response.status)

    p1 = product_db.Product.get_by_key_name('p1')
    self.assertTrue(client_db.Client.get_by_key_name('c2', p1) is None)

  def testDeleteArgValidation(self):
    # Client ID missing from URL.
    self._InitHandler('')
    self._handler.delete('p1', '')
    self.assertEqual(httplib.BAD_REQUEST, self._response.status)

    # Non-existing product ID.
    self._InitHandler('')
    self._handler.delete('p2', 'c2')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)

    # Non-existing client ID.
    self._InitHandler('')
    self._handler.delete('p1', 'c3')
    self.assertEqual(httplib.NOT_FOUND, self._response.status)
