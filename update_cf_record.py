#!/usr/bin/env python

import os
import sys
import requests

sys.path.insert(0, os.path.abspath('..'))
import CloudFlare as CF


email = ""
token=""
EXIT_SUCCESS=0
EXIT_FAILURE=1
NAME_TYPES=set(['AAAA', 'A', 'CNAME'])

def my_ip_address() -> tuple[str,str]:
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
        exit('{}: failed'.format(url))
    if ip_address == '':
        exit('{}: failed'.format(url))

    if ':' in ip_address:
        ip_address_type = 'AAAA'
    else:
        ip_address_type = 'A'

    return ip_address, ip_address_type

def delete_dns_record(cf: CF.CloudFlare, \
    zone_id: str, dns_name: str, record_type: str) -> bool:
    ''' Delete a dns record and return True if successful
    '''

    try:
        dns_records = cf.zones.dns_records.get(zone_id, params= {'name': dns_name, 'type': record_type})
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
    zone_id: str, dns_name: str, content: str, record_type: str, force: bool = False) -> bool:
    ''' Update/create a dns record and return True if successful
    '''

    try:
        dns_records = cf.zones.dns_records.get(zone_id, params= {'name': dns_name})
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones/dns_records %s - %d %s - api call failed' % (dns_name, e, e))
        return False

    updated = False

    # update the record - unless it's already correct
    for dns_record in dns_records:
        patch = False
        try:
            if record_type == dns_record['type']:
                if content == dns_record['content']:
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

    try:
        dns_record = cf.zones.dns_records.post(zone_id, data=new_record)
    except CF.exceptions.CloudFlareAPIError as e:
        print('/zones.dns_records.post {} - api call failed'.format(dns_name))
        return False

    print('CREATED: {} {}'.format(dns_name, content))
    return True

def usage():
    text="""usage: {0} ddns [fqdn-hostname] [-f]
       {0} set [fqdn-hostname] [type] [content] [-f]
       {0} delete [fqdn-hostname] [type]""".format(sys.argv[0])

    print(text)

def main():
    if len(sys.argv) < 3:
        usage()
        exit(EXIT_FAILURE)

    command = sys.argv[1]
    dns_name = sys.argv[2]
    zone_name = '.'.join(dns_name.split('.')[-2:])
    force = False

    if command == "ddns": 
        content, record_type = my_ip_address()
        print('MY IP: {} {}'.format(dns_name, content))
        force = len(sys.argv) > 3 and sys.argv[3] == "-f"
    elif command == "set":
        if len(sys.argv) < 5:
            usage()
            exit(EXIT_FAILURE)

        record_type = sys.argv[3]
        content = sys.argv[4]

        force = len(sys.argv) > 5 and sys.argv[5] == "-f"
    elif command == "delete":
        if len(sys.argv) != 4:
            usage()
            exit(EXIT_FAILURE)

        record_type = sys.argv[3]
    else:
        usage()
        exit(EXIT_FAILURE)

    cf = CF.CloudFlare(email=email, token=token)

    # grab the zone identifier
    try:
        params = {'name':zone_name}
        zones = cf.zones.get(params=params)
    except CF.exceptions.CloudFlareAPIError as e:
        exit('/zones %d %s - api call failed' % (e, e))
    except Exception as e:
        exit('/zones.get - %s - api call failed' % (e))

    if len(zones) == 0:
        exit('/zones.get - %s - zone not found' % (zone_name))

    if len(zones) != 1:
        exit('/zones.get - %s - api call returned %d items' % (zone_name, len(zones)))

    zone = zones[0]

    ret = False
    if command == "delete":
        ret = delete_dns_record(cf, zone['id'], dns_name, record_type)
    else:
        ret = dns_update(cf, zone['id'], dns_name, content, record_type, force)

    if (ret):
        exit(EXIT_SUCCESS)
    
    exit(EXIT_FAILURE)

if __name__ == '__main__':
    main()
