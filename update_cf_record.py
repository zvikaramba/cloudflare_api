#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import sys
import requests
import CloudFlare as CF

# Constants
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
NAME_TYPES = {'AAAA', 'A', 'CNAME'}
SUPPORTED_TYPES = {'AAAA', 'A', 'CNAME', 'MX', 'TXT', 'NS'}

# This list is adjustable - plus some v6 enabled services are needed
PUBLIC_IP_URLS = [
    'https://ifconfig.me/ip',
    'https://api.ipify.org',
    'http://myexternalip.com/raw',
    'http://www.trackip.net/ip',
    'http://myip.dnsomatic.com',
]

CONNECT_TIMEOUT = 5

class _batch:
    '''
    '''
    def __init__(self, email: 'str', token: 'str', records: 'list', force = False):
        self.email = email
        self.token = token
        self.records = records
        self.force = force

class RecordCache:
    CACHE_LIFETIME = 120
    CACHE_FILE = "/tmp/.ucr.cache.json"

    def __init__(self, cache_lifetime = CACHE_LIFETIME, cache_file = CACHE_FILE):
        '''
        '''
        self.cache = {}
        self.cache_lifetime = cache_lifetime
        self.cache_file = cache_file

    def load(self):
        '''
        '''
        if not os.path.isfile(self.cache_file):
            return

        cache_map = read_json_file(self.cache_file)
        if cache_map:
            self.cache = cache_map

    def save(self):
        '''
        '''
        if len(self.cache.keys()) == 0:
            return

        write_json_file(self.cache, self.cache_file)

    def get(self, key: 'object', default_value: 'object' = None) -> 'object':
        '''
        '''
        if key not in self.cache.keys():
            return default_value

        value = self.cache[key]
        delta = datetime.datetime.now() - value['timestamp']
        if delta.total_seconds() <= self.cache_lifetime:
            return value['data']

        self.cache.pop(key)
        return default_value

    def put(self, key: 'object', value: 'object') -> 'None':
        '''
        '''
        self.cache[key] = {'timestamp': datetime.datetime.now(), 'data': value}

    def pop(self, key: 'object') -> 'object':
        '''
        '''
        return self.cache.pop(key)

CACHE = RecordCache()

def get_public_address() -> 'tuple[str,str]':
    '''
    Return internet ip address and type
    '''
    ip_address = ''
    ip_address_type = ''

    for url in PUBLIC_IP_URLS:

        try:
            ip_address = requests.get(url=url, timeout=CONNECT_TIMEOUT).text
        except:
            continue

        if ip_address == '':
            continue

        if ':' in ip_address:
            ip_address_type = 'AAAA'
        else:
            ip_address_type = 'A'

        break

    return ip_address, ip_address_type

def parse_args(args: 'list' = None) -> 'argparse.Namespace':
    ''' Return parser and namespace containing parsed args
    '''

    # top-level parsers
    parser = argparse.ArgumentParser(description="Create and/or update CloudFlare DNS records")
    subparsers = parser.add_subparsers(dest='command')

    # top-level args
    subcmd_json = subparsers.add_parser("json")
    subcmd_json.add_argument("files", metavar="json file(s)", type=str, nargs='+')

    subcmd_ddns = subparsers.add_parser("ddns")
    subcmd_ddns.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_ddns.add_argument("--ttl", help='time to live in seconds', type=int, required = False)
    subcmd_ddns.add_argument("--proxied", help='proxied or not, 0 for False, True otherwise', type=int, required = False)
    subcmd_ddns.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_ddns.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_ddns.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_delete = subparsers.add_parser("delete")
    subcmd_delete.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_delete.add_argument("--type", help='record type', type=str, choices=SUPPORTED_TYPES, required=False)
    subcmd_delete.add_argument('--content', help='entry content', required=False)
    subcmd_delete.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_delete.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_set = subparsers.add_parser("set")
    subcmd_set.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_set.add_argument("type", help='record type', type=str, choices=SUPPORTED_TYPES)
    subcmd_set.add_argument('content', help='entry content')
    subcmd_set.add_argument("--ttl", help='time to live in seconds', type=int, required = False)
    subcmd_set.add_argument("--proxied", help='proxied or not, 0 for False, True otherwise', type=int, required = False)
    subcmd_set.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_set.add_argument("-p", "--priority", help='MX priority', type=int, required = False, default=10)
    subcmd_set.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_set.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_get_zone_id = subparsers.add_parser("get-zone-id")
    subcmd_get_zone_id.add_argument("name", help='fully qualified zone name')
    subcmd_get_zone_id.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_get_zone_id.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_get_zones = subparsers.add_parser("get-zones")
    subcmd_get_zones.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_get_zones.add_argument("-T", "--token", help='cloudflare api token', required=True)

    if args is None:
        parsed = parser.parse_args()
    else:
        parsed = parser.parse_args(args)

    # make sure a subcommand was specified
    if not parsed.command:
        print("Error: Specify a subcommend", file=sys.stderr)
        parser.print_help()
        sys.exit(EXIT_FAILURE)

    return parsed

def get_zones(cf: 'CF.CloudFlare', zone_name: 'str' = None) -> 'list':
    ''' Get the zone identifiers
    '''
    key = 'zones'
    try:
        zones = CACHE.get(key)
        if not zones:
            zones = cf.zones.get(params = {})
            CACHE.put(key, zones)

        for zone in zones:
            if zone['name'] == zone_name:
                return [zone]

    except CF.exceptions.CloudFlareAPIError as e:
        sys.exit('/zones %d %s - api call failed' % (e, e))
    except Exception as e:
        sys.exit('/zones.get - %s - api call failed' % (e))

    return zones

def get_zone_map(cf: 'CF.CloudFlare', zone_name: 'str' = None) -> 'dict':
    ''' Get the zone identifiers
    '''
    ret = {}
    for zone in get_zones(cf, zone_name):
        ret[zone['name']] = zone

    return ret

def get_zone_name(cf: 'CF.CloudFlare', name: 'str') -> 'str':
    '''
    Get zone name from fully-qualified name
    '''
    zone_map = get_zone_map(cf)
    split = name.split('.')

    for i in range(0, len(split)):
        current = ".".join(split[i:])
        if current in zone_map.keys():
            return current

    return ''

def get_zone_id(cf: 'CF.CloudFlare', zone_name: 'str') -> 'str':
    '''
    '''
    zones = get_zones(cf, zone_name)
    if len(zones) == 0:
        print('/zones.get - {} - zone not found'.format((zone_name)), file=sys.stderr)
        return ''
    elif len(zones) != 1:
        print('/zones.get - {} - api call returned {} items'.format(zone_name, len(zones)), file=sys.stderr)
        return ''

    return zones[0]['id']

def get_records(cf: 'CF.CloudFlare', zone_id: 'str', params: 'dict' = {}) -> 'list':
    ''' Get the records
    '''
    key = zone_id + '_records'
    try:
        records = CACHE.get(key)
        if not records:
            records = cf.zones.dns_records.get(zone_id, params = {})
            CACHE.put(key, records)

        matched_records = []
        for record in records:
            match = True
            for param in params.keys():
                if params[param] != record[param]:
                    match = False
                    break

            if match:
                matched_records.append(record)

        return matched_records

    except CF.exceptions.CloudFlareAPIError as e:
        sys.exit('/zones/dns_records %s - %d %s - api call failed' % (params['name'], e, e), file=sys.stderr)
    except Exception as e:
        sys.exit('/zones/dns_records - %s - api call failed' % (e))

def clear_record_cache(zone_id: 'str') -> 'None':
    ''' Clear the records from cache
    '''
    key = zone_id + '_records'
    CACHE.pop(key)

def delete_record(cf: 'CF.CloudFlare', zone_id: 'str', params: 'dict') -> 'bool':
    ''' Delete a dns record and return True if successful
    '''
    dns_records = get_records(cf, zone_id, params)

    ret = True
    for record in dns_records:
        try:
            cf.zones.dns_records.delete(zone_id, record['id'])
            print('DELETED: {}/{}/{}\n'.format(record['name'], record['type'], record['content']), file=sys.stderr)
        except CF.exceptions.CloudFlareAPIError as e:
            print('/zones.dns_records.delete %s - %d %s - api call failed' % (params['name'], e, e), file=sys.stderr)
            ret = False

    return ret

def add_update_record(cf: 'CF.CloudFlare', zone_id: 'str', params: 'dict', force: 'bool' = False) -> 'bool':
    ''' Update/create a dns record and return True if successful
    '''
    dns_records = get_records(cf, zone_id, params = {'name': params['name']})

    print('Params to set: {}'.format(params), file=sys.stderr)

    # update the record - unless it's already correct
    for record in dns_records:
        patch = False
        try:
            if record['type'] == params['type']:
                print('Found record: {}\n'.format(record), file=sys.stderr)

                for key in params.keys():
                    if key not in record:
                        continue

                    if record[key] != params[key]:
                        print('\tNeed to update {} from {} -> {}'\
                                .format(key, record[key], params[key]), file=sys.stderr)
                        patch = True
                        break

                if patch is False:
                    print('UNCHANGED: {} {}'.format(record['name'], record['content']), file=sys.stderr)
                    return True
            elif params['type'] in NAME_TYPES and record['type'] in NAME_TYPES:
                # we need to patch the record - check -f flag
                if not force:
                    print('Not changing record type from {} to {} - use -f'\
                        .format(record['type'], params['type']), file=sys.stderr)

                    return False

                patch = True
            else:
                # not the record we're interested in
                continue

            if patch:
                print('PATCH: {} ; Changing record type/content to {}/{}'.format(params['name'], params['type'], params['content']), file=sys.stderr)
                record = cf.zones.dns_records.patch(zone_id, record['id'], data=params)
            else:
                record = cf.zones.dns_records.put(zone_id, record['id'], data=params)

        except CF.exceptions.CloudFlareAPIError as e:
            if patch:
                print('/zones.dns_records.patch %s - %d %s - api call failed' % (params['name'], e, e), file=sys.stderr)
            else:
                print('/zones.dns_records.put %s - %d %s - api call failed' % (params['name'], e, e), file=sys.stderr)


        print('UPDATED: {} {} -> {}'.format(params['name'], record['content'], params['content']), file=sys.stderr)
        return True

    # no exsiting dns record to update - so create dns record
    try:
        record = cf.zones.dns_records.post(zone_id, data=params)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones.dns_records.post {} - api call failed'.format(params['name']), file=sys.stderr)
        return False

    print('CREATED: {} {}'.format(params['name'], params['content']), file=sys.stderr)
    return True

def clean_params(params: 'dict') -> 'dict':
    '''
    Extract and/or convert fields from p into
    params for use by cf api
    '''
    new_params = {}

    keys = ['name', 'type', 'content', 'ttl', 'proxied', 'priority', 'force']
    bool_keys = set(['proxied'])
    for key in keys:
        if (key not in params) or (params[key] is None):
            continue

        if key in bool_keys and not isinstance(params[key], bool):
            new_params[key] = (params[key] != 0)
        else:
            new_params[key] = params[key]

    return new_params

def process_records(batch: '_batch') -> 'bool':
    '''
    '''
    required_keys = ['action', 'params']
    ret = True

    cf = CF.CloudFlare(email=batch.email, token=batch.token)

    for record in batch.records:
        for key in required_keys:
            if key not in record:
                print("Error: Missing key {}".format(key), file=sys.stderr)
                ret = False
                continue

        if record['action'] == "get-zones":
            for zone in get_zones(cf):
                print(zone['name'])

            continue

        params = record['params']
        zone_name = get_zone_name(cf, params['name'])
        zone_id = get_zone_id(cf, zone_name)

        force = batch.force
        if 'force' in params:
            force = force or params['force']
            del params['force']

        if record['action'] == "get-zone-id":
            print(zone_id, end='', flush=True)
            continue

        if record['action'] == "delete":
            if not delete_record(cf, zone_id, params):
                ret = False

            continue

        if record['action'] == "ddns":
            content, type = get_public_address()
            if len(content) == 0:
                print("Failed to get public ip address", file=sys.stderr)
                continue

            params['content'] = content
            params['type'] = type

        # default action: 'set'
        add_update_record(cf, zone_id, params, force)

    return ret

def read_json_file(path: 'str') -> 'object':
    '''
    Unmarshall json from file
    '''
    with open(path, mode='rt') as file:
        try:
            decoded = json.load(file)
            if isinstance(decoded, dict):
                return decoded

            print("Error: Invalid format", file=sys.stderr)
        except json.JSONDecodeError:
            print("Error: Failed to parse json", file=sys.stderr)
        except:
            print("Error: failed to read file " + file, file=sys.stderr)

    return None

def write_json_file(obj, path: 'str') -> 'bool':
    '''
    Unmarshall json from file
    '''
    with open(path, mode='wt') as file:
        try:
            json_str = json.dumps(obj)
            if file.write(json_str) >= len(json_str):
                return True
        except TypeError:
            print("Error: Failed to create json", file=sys.stderr)
        except:
            print("Error: failed to write file " + file, file=sys.stderr)

    return False

def main():
    '''
    Entrypoint
    '''
    batches = []
    ret = True

    # Parse command line
    parsed = vars(parse_args())

    # Read in json files
    if parsed['command'] == 'json':
        required_keys = ['email', 'token', 'records']
        for file in parsed['files']:
            decoded = read_json_file(file)
            if not decoded:
                ret = False
                continue

            missing_key = False
            for key in required_keys:
                if key not in decoded:
                    print("Error: Missing key {}".format(key), file=sys.stderr)
                    missing_key = True
                    break

            if missing_key:
                ret = False
                continue

            force = 'force' in decoded and decoded['force']

            if type(decoded['records']) is not list:
                print("Error: Invalid record format", file=sys.stderr)
                ret = False
                continue

            batches.append(_batch(decoded['email'], decoded['token'], decoded['records'], force = force))
    else:
        record = {
            "action": parsed['command'],
            "params": clean_params(parsed)
        }

        batches.append(_batch(parsed['email'], parsed['token'], [record]))

    for batch in batches:
        # run command handler
        if not process_records(batch):
            ret = False

    return ret

if __name__ == '__main__':
    CACHE.load()
    ret = main()
    CACHE.save()

    if ret:
        sys.exit(EXIT_SUCCESS)

    sys.exit(EXIT_FAILURE)
