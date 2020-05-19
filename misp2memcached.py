#!/usr/bin/env python3

# MISP2memcached
# misp2memcached.py
# Author: Ján Trenčanský
# License: MIT

import yaml
import parsers.misp
import outputs.memcached


misp = None
memcached = None

if __name__ == '__main__':
    with open("config.yml", "r") as config_file:
        try:
            config = yaml.safe_load(config_file)
        except yaml.YAMLError as e:
            print(e)
    memcached = outputs.memcached.Memcached(config['memcached']['host'], config['memcached']['port'])
    misp = parsers.misp.Misp(config['misp']['url'], config['misp']['token'], memcached,
                             config['misp']['ignore_cert_errors'])
    if memcached.stats() == 0:
        misp.event_timestamp = config['misp']['initial_event_timestamp']
    else:
        misp.event_timestamp = config['misp']['refresh_event_timestamp']
    if config['hash']['enabled']:
        misp.load_hash(config['hash']['expires'])
    if config['network']['enabled']:
        misp.load_network(config['hash']['expires'])
    if config['web']['enabled']:
        misp.load_web(config['hash']['expires'])
