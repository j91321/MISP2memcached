# This file is part of MISP2memcached
# memcached.py - Insert values into memcached in expected format
# Author: Ján Trenčanský
# License: MIT

import pymemcache


class Memcached:
    host = None
    port = None
    client = None

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = pymemcache.client.base.Client((self.host, self.port))
        memcache_value = self.client.get("misp-stats")
        if memcache_value is None:
            self.client.set("misp-stats", 0)

    def stats(self):
        memcache_value = self.client.get("misp-stats")
        return int(memcache_value)

    def insert(self, namespace, lookup_value, tag, expire):
        lookup_value = lookup_value.strip()
        tag = tag.replace(',', "")  # Remove "," since it's being used as separator in memcached
        key = namespace + ":" + lookup_value
        memcache_value = self.client.get(key)
        if memcache_value:
            existing_tags = memcache_value.decode("utf-8").split(',')
            # print("Existing tags for {0}: {1}".format(key, existing_tags))
            if tag not in existing_tags:
                self.client.append(key, "," + tag, expire=expire)
                return True
            else:
                return False
        else:
            # print(key, tag)
            self.client.set(key, tag, expire=expire)
            self.client.incr("misp-stats", 1, True)
            return True
