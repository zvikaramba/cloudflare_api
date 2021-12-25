#!/usr/bin/env python3

import argparse
import json
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

def get_public_address() -> tuple[str,str]:
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

def parse_args(args: list = None) -> argparse.Namespace:
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
    subcmd_set.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_set.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_set_mx = subparsers.add_parser("set-mx")
    subcmd_set_mx.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_set_mx.add_argument('content', help='fully qualified domain name')
    subcmd_set_mx.add_argument("-p", "--priority", help='MX priority', type=int, required = False, default=10)
    subcmd_set_mx.add_argument("--ttl", help='time to live in seconds', type=int, required = False)
    subcmd_set_mx.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_set_mx.set_defaults(type="MX")
    subcmd_set_mx.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_set_mx.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_get_zone_id = subparsers.add_parser("get-zone-id")
    subcmd_get_zone_id.add_argument("name", help='fully qualified zone name')
    subcmd_get_zone_id.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_get_zone_id.add_argument("-T", "--token", help='cloudflare api token', required=True)

    subcmd_get_zones = subparsers.add_parser("get-zones")
    subcmd_get_zones.add_argument("-E", "--email", help='cloudflare email', required=True)
    subcmd_get_zones.add_argument("-T", "--token", help='cloudflare api token', required=True)

    if args == None:
        parsed = parser.parse_args()
    else:
        parsed = parser.parse_args(args)

    # make sure a subcommand was specified
    if not parsed.command:
        print("Error: Specify a subcommend")
        parser.print_help()
        exit(EXIT_FAILURE)

    # Some final processing
    if (parsed.command != "get_zones"):
        split = parsed.name.split('.')
        if len(split) < 2:
            print("Invalid name {} specified".format(parsed.name))
            exit(EXIT_FAILURE)

        parsed.zone_name = ".".join(split[-2:])

    if parsed.command == "ddns":
        parsed.content, parsed.type = get_public_address()
        if len(parsed.content) == 0:
            print("Failed to get public ip address")
            exit(EXIT_FAILURE)

    elif parsed.command == "set" and parsed.type == "MX":
        print("Use set-mx command instead")
        exit(EXIT_FAILURE)

    return parsed

def get_zones(cf: CF.CloudFlare, zone_name: str = None) -> list:
    # grab the zone identifier
    try:
        params = dict()
        if zone_name:
            params['name'] = zone_name

        zones = cf.zones.get(params=params)
    except CF.exceptions.CloudFlareAPIError as e:
        exit('/zones %d %s - api call failed' % (e, e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    return zones

def get_zone_id(cf: CF.CloudFlare, zone_name: str) -> str:
    '''
    '''
    zones = get_zones(cf, zone_name)
    if len(zones) == 0:
        print('/zones.get - {} - zone not found'.format((zone_name)))
        return ''
    elif len(zones) != 1:
        print('/zones.get - {} - api call returned {} items'.format(zone_name, len(zones)))
        return ''

    return zones[0]['id']

def delete_record(cf: CF.CloudFlare, zone_id: str, params: dict) -> bool:
    ''' Delete a dns record and return True if successful
    '''

    try:
        dns_records = cf.zones.dns_records.get(zone_id, params = params)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones/dns_records %s - %d %s - api call failed' % (params['name'], e, e))
        return False

    ret = True
    for record in dns_records:
        try:
            del_record = cf.zones.dns_records.delete(zone_id, record['id'])
            print('DELETED: {}/{}/{}\n'.format(record['name'], record['type'], record['content']))
        except CF.exceptions.CloudFlareAPIError as e:
            print('/zones.dns_records.delete %s - %d %s - api call failed' % (params['name'], e, e))
            ret = False

    return ret

def add_update_record(cf: CF.CloudFlare, zone_id: str, params: dict, force: bool = False) -> bool:
    ''' Update/create a dns record and return True if successful
    '''

    try:
        dns_records = cf.zones.dns_records.get(zone_id, params = {'name': params['name']})
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones/dns_records %s - %d %s - api call failed' % (params['name'], e, e))
        return False

    print('Params to set: {}'.format(params))

    # update the record - unless it's already correct
    for record in dns_records:
        patch = False
        try:
            if record['type'] == params['type']:
                print('Found record: {}\n'.format(record))

                for key in params.keys():
                    if record[key] != params[key]:
                        print('\tNeed to update {} from {} -> {}'\
                                .format(key, record[key], params[key]))
                        patch = True
                        break

                if patch == False: # and params['content'] == record['content']:
                    print('UNCHANGED: {} {}'.format(record['name'], record['content']))
                    return True
            elif params['type'] in NAME_TYPES and record['type'] in NAME_TYPES:
                # we need to patch the record - check -f flag
                if not force:
                    print('Not changing record type from {} to {} - use -f'\
                        .format(record['type'], params['type']))

                    return False

                patch = True
            else:
                # not the record we're interested in
                continue

            if patch:
                print('PATCH: {} ; Changing record type/content to {}/{}'.format(params['name'], params['type'], params['content']))
                record = cf.zones.dns_records.patch(zone_id, record['id'], data=params)
            else:
                record = cf.zones.dns_records.put(zone_id, record['id'], data=params)

        except CF.exceptions.CloudFlareAPIError as e:
            if patch:
                print('/zones.dns_records.patch %s - %d %s - api call failed' % (params['name'], e, e))
            else:
                print('/zones.dns_records.put %s - %d %s - api call failed' % (params['name'], e, e))


        print('UPDATED: {} {} -> {}'.format(params['name'], record['content'], params['content']))
        return True

    # no exsiting dns record to update - so create dns record
    try:
        record = cf.zones.dns_records.post(zone_id, data=params)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones.dns_records.post {} - api call failed'.format(params['name']))
        return False

    print('CREATED: {} {}'.format(params['name'], params['content']))
    return True

def generate_handler(p: argparse.Namespace):
    ''' argparse.Namespace -> function[str]
    Get command handler
    '''
    params = {}

    keys = ['name', 'type', 'content', 'ttl', 'proxied', 'priority']
    bool_keys = set(['proxied'])
    for key in keys:
        if key not in p:
            continue
        elif p[key] is None:
            continue

        if key in bool_keys:
            params[key] = (p[key] != 0)
        else:
            params[key] = p[key]

    def _delete_record():
        return delete_record(p['cf'], p['zone_id'], params)

    def _set_record():
        return add_update_record(p['cf'], p['zone_id'], params, p['force'])

    def _get_zone_id():
        print(p['zone_id'], end='', flush=True)
        return True

    def _get_zones():
        zones = _get_zones(p['cf'])
        for zone in zones:
            print(zone['name'])

        return True

    def get_handler(name: str):
        ''' str -> function
        '''
        func = _set_record
        if name == "get-zone-id":
            func = _get_zone_id
        elif name == "get-zones":
            func = _get_zones
        elif name == "delete":
            func = _delete_record

        return func

    return get_handler

def main():
    '''
    Entrypoint
    '''
    parsed = parse_args()
    parsed.cf = CF.CloudFlare(email=parsed.email, token=parsed.token)

    # get zones
    parsed.zone_id = get_zone_id(parsed.cf, parsed.zone_name)
    if len(parsed.zone_id) == 0:
        print('Failed to get/find zone-id for {}'.format(parsed.zone_name))
        exit(EXIT_FAILURE)

    # run command handler
    ret = generate_handler(vars(parsed))(parsed.command)()
    if (ret):
        exit(EXIT_SUCCESS)

    exit(EXIT_FAILURE)

if __name__ == '__main__':
    main()
