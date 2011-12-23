# Copyright 2011 Google Inc.
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

import json
from google.appengine.ext import db
from google.appengine.ext import webapp
from model import client as client_db
from model import metric as metric_db
from model import product as product_db

class ClientHandler(webapp.RequestHandler):
  """A class to handle creating and querying clients."""

  def get(self, product_id, client_id):
    """Responds with information about a client.

    Responds with a JSON encoded product ID, client ID, description and metric
    IDs for a given product_id and client_id pair. If the product or client
    doesn't exist, responds with a 404.

    Args:
      product_id. The product ID.
      client_id: The client ID.
    """
    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    client = client_db.Client.get_by_key_name(client_id, product)
    if not client:
      self.error(404)  # Not found.
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

    Adds a client to the data store. The product and client IDs should be
    specified in the URL and the description should be specified as POST
    parameters in the request. Responds with a 200 on success or a 400 if there
    are invalid parameters.

    Args:
      product_id: The product ID.
      client_id: The client ID.
    """
    description = self.request.get('description', None)
    if not description:
      self.error(400)  # Bad request.
      return

    product = product_db.Product.get_by_key_name(product_id)
    if not product:
      self.error(404)  # Not found.
      return

    # Creates a new client or updates the description for an existing client.
    client = client_db.Client(key_name=client_id, parent=product,
                              description=description)
    client.put()

