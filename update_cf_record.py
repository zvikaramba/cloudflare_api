#!/usr/bin/env python3

import sys
import requests
import argparse
import CloudFlare as CF

# Constants
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
NAME_TYPES = {'AAAA', 'A', 'CNAME'}
SUPPORTED_TYPES = {'AAAA', 'A', 'CNAME', 'MX', 'TXT', 'NS'}

def get_public_address() -> tuple[str,str]:
    '''
    Return internet ip address and type
    '''

    # This list is adjustable - plus some v6 enabled services are needed
    # url = 'http://myip.dnsomatic.com'
    # url = 'http://www.trackip.net/ip'
    # url = 'http://myexternalip.com/raw'
    #url = 'https://api.ipify.org'
    url = 'https://ifconfig.me/ip'
    try:
        ip_address = requests.get(url).text
    except:
        print('{}: failed'.format(url))
        exit(EXIT_FAILURE)

    if ip_address == '':
        print('{}: failed'.format(url))
        exit(EXIT_FAILURE)

    if ':' in ip_address:
        ip_address_type = 'AAAA'
    else:
        ip_address_type = 'A'

    return ip_address, ip_address_type

#def parser_handle_defaults()

def parse_args(args: list = None) -> argparse.Namespace:
    ''' Return namespace containing pased args
    '''
    # top-level parsers
    parser = argparse.ArgumentParser(description="Create and/or update CloudFlare DNS records")
    subparsers = parser.add_subparsers(dest='subparser_name')

    # top-level args
    #parser.add_argument("-E", "--email", help='cloudflare email', required=True, default="<cf_email>")
    #parser.add_argument("-T", "--token", help='cloudflare api token', required=True, default="<cf_token>")
    parser.add_argument("-E", "--email", help='cloudflare email', default="<cf_email>")
    parser.add_argument("-T", "--token", help='cloudflare api token', default="<cf_token>")

    subcmd_set = subparsers.add_parser("ddns")
    subcmd_set.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_set.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_set.add_argument("--ttl", help='time to live in seconds', type=int, default=1800)
    subcmd_set.add_argument("--proxied", help='record is proxied or not', action="store_true")

    subcmd_set = subparsers.add_parser("set")
    subcmd_set.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_set.add_argument("type", help='record type', type=str, choices=SUPPORTED_TYPES)
    subcmd_set.add_argument('content', help='entry content')
    subcmd_set.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_set.add_argument("--ttl", help='time to live in seconds', type=int, default=1800)
    subcmd_set.add_argument("--proxied", help='record is proxied or not', action="store_true")

    subcmd_set_mx = subparsers.add_parser("set-mx")
    subcmd_set_mx.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_set_mx.add_argument('content', help='fully qualified domain name')
    subcmd_set_mx.add_argument("priority", help='MX priority', type=int, default=10)
    subcmd_set_mx.add_argument("-f", "--force", help='Overwrite record if present', action="store_true")
    subcmd_set_mx.add_argument("--ttl", help='time to live in seconds', type=int, default=1800)
    subcmd_set_mx.set_defaults(type="MX")

    subcmd_delete = subparsers.add_parser("delete")
    subcmd_delete.add_argument("name", metavar="fqdn", help='fully qualified record name')
    subcmd_delete.add_argument("--type", help='record type', type=str, choices=SUPPORTED_TYPES, required=False, default=None)
    subcmd_delete.add_argument('--content', help='entry content', required=False, default=None)

    subcmd_get_zone_id = subparsers.add_parser("get-zone-id")
    subcmd_get_zone_id.add_argument("name", help='fully qualified zone name')

    subcmd_get_zones = subparsers.add_parser("get-zones")

    if args == None:
        parsed = parser.parse_args()
    else:
        parsed = parser.parse_args(args)

    # Some final processing
    if (parsed.subparser_name != "get_zones"):
        split = parsed.name.split('.')
        if len(split) < 2:
            print("Invalid name {} specified".format(parsed.name))
            exit(EXIT_FAILURE)

        parsed.zone_name = ".".join(split[-2:])

    if (parsed.subparser_name == "ddns"):
        parsed.content, parsed.type = get_public_address()

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

def get_zone_id(cf: CF.CloudFlare, zone_name) -> str:
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

def delete_dns_record(cf: CF.CloudFlare, \
    zone_id: str, dns_name: str, record_type: str, extra_params: dict = {}) -> bool:
    ''' Delete a dns record and return True if successful
    '''

    try:
        params = dict(extra_params)
        params['name'] = dns_name
        params['type'] = record_type

        dns_records = cf.zones.dns_records.get(zone_id, params = params)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones/dns_records %s - %d %s - api call failed' % (dns_name, e, e))
        return False

    ret = True
    for dns_record in dns_records:
        try:
            print('DELETE: {}/{} ;'.format(dns_name, record_type))
            del_record = cf.zones.dns_records.delete(zone_id, dns_record['id'])
        except CF.exceptions.CloudFlareAPIError as e:
            print('/zones.dns_records.delete %s - %d %s - api call failed' % (dns_name, e, e))
            ret = False

    print('DELETED: {}/{}'.format(dns_name, record_type))
    return ret

def dns_update(cf: CF.CloudFlare, \
    zone_id: str, dns_name: str, content: str, record_type: str, \
        force: bool = False, extra_params: dict = {}) -> bool:
    ''' Update/create a dns record and return True if successful
    '''

    try:
        params = dict(extra_params)
        params['name'] = dns_name

        dns_records = cf.zones.dns_records.get(zone_id, params = params)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones/dns_records %s - %d %s - api call failed' % (dns_name, e, e))
        return False

    updated = False
    print('Params to set: {}'.format(params))

    # update the record - unless it's already correct
    for dns_record in dns_records:
        patch = False
        try:
            if record_type == dns_record['type']:
                print('Found record: {}\n'.format(dns_record))

                for key in extra_params.keys():
                    if dns_record[key] != extra_params[key]:
                        print('\tNeed to update {} from {} -> {}'\
                                .format(key, dns_record[key], extra_params[key]))
                        patch = True
                        break

                if patch == False and content == dns_record['content']:
                    print('UNCHANGED: {} {}'.format(dns_name, content))
                    return True
            elif record_type in NAME_TYPES and dns_record['type'] in NAME_TYPES:
                # we need to patch the record - check -f flag
                if not force:
                    print('Not changing record type from {} to {} - use -f'\
                        .format(dns_record['type'], record_type))

                    return False

                patch = True
            else:
                # not the record we're interested in
                continue

            new_record = {
                'name': dns_name,
                'type': record_type,
                'content': content,
                'proxied': dns_record['proxied']
            }

            new_record.update(extra_params)

            if patch:
                print('PATCH: {} ; Changing record type/content to {}/{}'.format(dns_name, record_type, content))
                dns_record = cf.zones.dns_records.patch(zone_id, dns_record['id'], data=new_record)
            else:
                dns_record = cf.zones.dns_records.put(zone_id, dns_record['id'], data=new_record)

        except CF.exceptions.CloudFlareAPIError as e:
            if patch:
                print('/zones.dns_records.patch %s - %d %s - api call failed' % (dns_name, e, e))
            else:
                print('/zones.dns_records.put %s - %d %s - api call failed' % (dns_name, e, e))


        print('UPDATED: {} {} -> {}'.format(dns_name, dns_record['content'], content))
        return True

    # no exsiting dns record to update - so create dns record
    new_record = {
        'name':dns_name,
        'type':record_type,
        'content':content
    }

    new_record.update(extra_params)

    try:
        dns_record = cf.zones.dns_records.post(zone_id, data=new_record)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones.dns_records.post {} - api call failed'.format(dns_name))
        return False

    print('CREATED: {} {}'.format(dns_name, content))
    return True


def main():
    '''
    Entrypoint
    '''
    parsed = parse_args()
    cf = CF.CloudFlare(email=parsed.email, token=parsed.token)

    # get zones
    zone_id = get_zone_id(cf, parsed.zone_name)
    if len(zone_id) == 0:
        exit(EXIT_FAILURE)

    if command == "ddns": 
        content, record_type = get_public_address()
        print('MY IP: {} {}'.format(dns_name, content))
        force = "-f" in sys.argv[3:]
    elif command == "set-mx":
        if len(sys.argv) < 5:
            usage()
            exit(EXIT_FAILURE)

        record_type = "MX"
        content = sys.argv[3]
        priority = sys.argv[4]

        force = "-f" in sys.argv[4:]
    elif command == "set":
        if len(sys.argv) < 5:
            usage()
            exit(EXIT_FAILURE)

        record_type = sys.argv[3]
        content = sys.argv[4]
        priority = sys.argv[5]

        force = "-f" in sys.argv[5:]
    elif command == "delete":
        if len(sys.argv) != 4:
            usage()
            exit(EXIT_FAILURE)

        record_type = sys.argv[3]
    elif command == "get-zone-id":
        print(zone_id, end='', flush=True)
        exit(EXIT_SUCCESS)
    else:
        usage()
        exit(EXIT_FAILURE)

    extra_params = {}

    ret = False
    if command == "delete":
        ret = delete_dns_record(cf, zone_id, dns_name, record_type, extra_params = extra_params)
    else:
        if record_type == "MX":
            try:
                extra_params['priority'] = int(priority)
            except:
                extra_params['priority'] = 10

        ret = dns_update(cf, zone_id, dns_name, content, record_type, force, extra_params = extra_params)

    if (ret):
        exit(EXIT_SUCCESS)
    
    exit(EXIT_FAILURE)

if __name__ == '__main__':
    main()
