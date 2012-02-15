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
import urlparse
from google.appengine.ext import webapp
from model import client as client_db
from model import metric as metric_db
from model import product as product_db

class ClientHandler(webapp.RequestHandler):
  """A class to handle creating, reading, updating and deleting clients.

  Handles GET, POST, PUT and DELETE requests for /clients/<product>/ and
  /clients/<product>/<client>. All functions have the same signature, even
  though they may not use all the parameters, so that a single route can be
  used for the handler.
  """

  def get(self, product_id, client_id):
    """Responds with information about all clients or a specific client.

    /clients/<product>/
      Responds with a JSON encoded object that contains a list of client IDs for
      the given product.
    /clients/<product>/<client>
      Responds with a JSON encoded object of the product ID, client ID,
      description and child metric IDs for the given product and client.

    Args:
      product_id. The product ID.
      client_id: The client ID. May be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    if not client_id:
      client_keys = client_db.Client.all(keys_only=True)
      client_keys.ancestor(product)
      client_ids = [key.name() for key in client_keys]

      result = {'product_id': product.key().name(),
                'client_ids': client_ids}
    else:
      client = client_db.Client.get_by_key_name(client_id, product)
      if not client:
        self.error(httplib.NOT_FOUND)
        return

      metric_keys = metric_db.Metric.all(keys_only=True)
      metric_keys.ancestor(client)
      metric_ids = [key.name() for key in metric_keys]

      result = {'product_id': product.key().name(),
                'client_id': client.key().name(),
                'description': client.description,
                'metric_ids': metric_ids}

    self.response.headers['Content-Type'] = 'application/json'
    json.dump(result, self.response.out)

  def post(self, product_id, client_id):
    """Creates a new client.

    /clients/<product>/
      Creates a new client. The client ID and description should be specified
      in the body of the request.
    /clients/<product>/<client>
      Unused.

    Args:
      product_id: The product ID.
      client_id: The client ID. Must be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    if client_id:
      self.error(httplib.BAD_REQUEST)
      return

    client_id = self.request.get('client_id', None)
    description = self.request.get('description', None)
    if not client_id or not description:
      self.error(httplib.BAD_REQUEST)
      return

    # Make sure that this client ID doesn't already exist.
    if client_db.Client.get_by_key_name(client_id, product):
      self.error(httplib.BAD_REQUEST)
      return

    # Create a new client.
    client = client_db.Client(key_name=client_id, parent=product,
                              description=description)
    client.put()

  def put(self, product_id, client_id):
    """Updates a client.

    /clients/<product>/
      Unused.
    /clients/<product>/<client>
      Updates a client. The description should be specified in the body of the
      request.

    Args:
      product_id: The product ID.
      client_id: The client ID. Must not be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    if not client_id:
      self.error(httplib.BAD_REQUEST)
      return

    # Make sure that this client ID already exists.
    if not client_db.Client.get_by_key_name(client_id, product):
      self.error(httplib.BAD_REQUEST)
      return

    # Appengine bug: parameters in body aren't parsed for PUT requests.
    # http://code.google.com/p/googleappengine/issues/detail?id=170
    params = urlparse.parse_qs(self.request.body)
    description = params.get('description', [None])[0]
    if not description:
      self.error(httplib.BAD_REQUEST)
      return

    # Update the client.
    client = client_db.Client(key_name=client_id, parent=product,
                              description=description)
    client.put()

  def delete(self, product_id, client_id):
    """Deletes a client.

    /clients/<product>/
      Unused
    /clients/<product>/<client>
      Deletes the specified client.

    Args:
      product_id: The product ID.
      client_id: The client ID. Must not be empty.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(httplib.NOT_FOUND)
      return

    if not client_id:
      self.error(httplib.BAD_REQUEST)
      return

    # Delete the client.
    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(httplib.BAD_REQUEST)
      return
    
    client.delete()
