# This file is part of MISP2memcached
# misp.py - Load IOCs from MISP instance into memcached
# Author: Ján Trenčanský
# License: MIT

import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class Misp:
    url = None
    token = None
    ignore_cert_errors = None
    memcached = None
    event_timestamp = None

    def __init__(self, url, token, memcached, ignore_cert_errors=False):
        self.url = url
        self.token = token
        self.ignore_cert_errors = ignore_cert_errors
        self.memcached = memcached

    def fetch_data(self, misp_types):
        headers = {
            'Authorization': self.token,
            'Accept': 'application/json',
            'Content-type': 'application/json',
        }
        data = '{"returnFormat":"json",' \
               '"type": {"OR":' + json.dumps(misp_types) + '},' \
               '"to_ids":"yes",' \
               '"event_timestamp":"' + self.event_timestamp + '"}'
        if self.ignore_cert_errors:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(self.url+'/attributes/restSearch', headers=headers, data=data,
                                 verify=(not self.ignore_cert_errors))
        return response.text

    """
    Sources:
    md5, sha1, sha256, sha512, imphash, 
    filename|imphash, filename|md5, filename|sha1, filename|sha256, filename|sha512
    Destination namespace: 
    misp-md5
    misp-sha1
    misp-sha256
    misp-sha512
    misp-imphash
    """
    def load_hash(self, expire=0):
        misp_types = ["md5", "sha1", "sha256", "sha512", "imphash"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            namespace = "misp-" + event['type']
            lookup_value = event['value']
            event_id = event['event_id']
            tag = event_id+"#"+event['type']
            self.memcached.insert(namespace, lookup_value, tag, expire)
        misp_types = ["filename|imphash", "filename|md5", "filename|sha1", "filename|sha256", "filename|sha512"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            event_types = event['type'].split("|")
            namespace2 = "misp-" + event_types[1]
            lookup_values = event['value'].split("|")
            lookup_value2 = lookup_values[1]
            event_id = event['event_id']
            tag = event_id + "#" + event['type']
            self.memcached.insert(namespace2, lookup_value2, tag, expire)

    """
    Sources:
    ip-dst, ip-src, domain
    ip-dst|port, ip-src|port, domain|ip
    Destination namespace:
    misp-ip
    misp-domain
    """
    def load_network(self, expire=0):
        misp_types = ["ip-dst", "ip-src", "domain"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            if event['type'] in ["ip-src", "ip-dst"]:
                event_type = "ip"
            else:
                event_type = event['type']
            namespace = "misp-" + event_type
            lookup_value = event['value']
            event_id = event['event_id']
            tag = event_id + "#" + event['type']
            self.memcached.insert(namespace, lookup_value, tag, expire)
        misp_types = ["ip-dst|port", "ip-src|port", "domain|ip"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            if event['type'] in ["ip-src|port", "ip-dst|port"]:
                namespace = "misp-ip"
                lookup_values = event['value'].split("|")
                lookup_value1 = lookup_values[0]
                event_id = event['event_id']
                tag = event_id + "#" + event['type']
                self.memcached.insert(namespace, lookup_value1, tag, expire)
            elif event['type'] == "domain|ip":
                event_types = event['type'].split("|")
                namespace1 = "misp-" + event_types[0]
                namespace2 = "misp-" + event_types[1]
                lookup_values = event['value'].split("|")
                event_id = event['event_id']
                tag = event_id + "#" + event['type']
                self.memcached.insert(namespace1, lookup_values[0], tag, expire)
                self.memcached.insert(namespace2, lookup_values[1], tag, expire)

    """
    Sources:
    url, user-agent
    Destination namespace:
    misp-url
    misp-user-agent - problem can contain whitespaces
    """
    def load_web(self, expire=0):
        misp_types = ["url"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            namespace = "misp-" + event['type']
            lookup_value = event['value']
            event_id = event['event_id']
            tag = event_id + "#" + event['type']
            self.memcached.insert(namespace, lookup_value, tag, expire)

    """
    Sources:
    mutex, named pipe, regkey
    Destination namespace:
    misp-mutex
    misp-named-pipe
    misp-regkey
    """
    def load_other(self, expire=0):
        misp_types = ["mutex", "named pipe", "regkey"]
        results = self.fetch_data(misp_types)
        events = json.loads(results)['response']['Attribute']
        for event in events:
            if event['type'] == "named pipe":
                namespace = "misp-named-pipe"
            else:
                namespace = "misp-" + event['type']
            lookup_value = event['value']
            event_id = event['event_id']
            tag = event_id + "#" + event['type']
            self.memcached.insert(namespace, lookup_value, tag, expire)
