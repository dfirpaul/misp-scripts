#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import re
import logging
import json
import time
from pymisp import PyMISP
import argparse
from tqdm import tqdm
import sys

cve_pattern = re.compile('CVE-\d{4}-\d{4}')


def load_file(filename, ip_column, cve_column, cve_pattern, delimiter=','):
    output = {}
    try:
        with open(filename, 'r') as csv_file:
            cve_uniq = []
            csv_data = csv.reader(csv_file, delimiter=delimiter)
            for row in csv_data:
                try:
                    vuln_cell = row[cve_column]
                    cves = re.findall(cve_pattern, vuln_cell)
                    cve_uniq += cves
                except Exception as e_parse_row:
                    logging.info('Cannot parse row, exception: {}'.format(str(e_parse_row)))
            cve_uniq = list(set(cve_uniq))
            for cve in cve_uniq:
                output[cve] = []
                csv_file.seek(0)
                for row in csv_data:
                    try:
                        if cve in row[cve_column]:
                            output[cve].append(row[ip_column])
                    except Exception as e_parse_row:
                        logging.info('Cannot parse row, exception: {}'.format(str(e_parse_row)))
    except Exception as e_openfile:
        logging.error('Error while opening the file: {}'.format(str(e_openfile)))
        return False
    return output


def update_event_tags(data, misp):
    # cve_ids = {}
    result = misp.search(controller='attributes',
                         values=list(data.keys()))
    # print(result)
    event_ids = set()
    attribute_uuids = {}
    for attribute in result['response']['Attribute']:
        if attribute['value'] in data:
            # print(attribute)
            event_ids.add(attribute['event_id'])
            attribute_uuids[attribute['value']] = attribute['uuid']
    # print(event_ids)
    # print(attribute_uuids)
    for event_id in event_ids:
        event = misp.get(event_id)
        attributes = event['Event']['Attribute']
        for attribute in attributes:
            if attribute['value'] in data:
                if attribute.get('Tag'):
                    for tag in attribute['Tag']:
                        if 'is_vulnerable' in tag['name']:
                            # print('Tag:', tag)
                            misp.untag(attribute['uuid'], tag['name'])
    updated_attributes_count = 0
    for cve, uuid in tqdm(attribute_uuids.items()):
        # print(cve, uuid)
        tag_value = len(data[cve])
        tag = 'is_vulnerable:{}'.format(str(tag_value))
        # print(tag)
        response = misp.tag(uuid, tag)
        # print(response)
        updated_attributes_count += 1
    return 'Updated attributes: {}'.format(str(updated_attributes_count))


def init(url, key, verifycert):
    try:
        return PyMISP(url, key, verifycert, 'json')
    except Exception as e:
        return str(e)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Assing tags with number of internal vulnerable hosts to attributes.')
    parser.add_argument("-f", "--file", required=True, help="CSV file with information about vulnerabilities.")
    parser.add_argument("-i", "--ipcolumn", required=False, type=int, default=1, help="Index of a column with IP address.")
    parser.add_argument("-c", "--cvecolumn", required=False, type=int, default=4, help="Index of a column with CVE.")
    parser.add_argument("-d", "--delimiter", required=False, type=str, default=',', help="CSV delimiter.")
    parser.add_argument("-u", "--url", required=True, type=str, help="MISP URL.")
    parser.add_argument("-k", "--key", required=True, type=str, help="MISP key.")
    parser.add_argument('--verify-cert', dest='misp_verifycert', action='store_true')
    parser.add_argument('--no-verify-cert', dest='misp_verifycert', action='store_false')
    parser.set_defaults(misp_verifycert=True)
    args = parser.parse_args()

    misp_url = args.url
    misp_key = args.key
    misp_verifycert = args.misp_verifycert
    if not misp_verifycert:
        import warnings
        warnings.filterwarnings("ignore")
    misp = init(misp_url, misp_key, misp_verifycert)
    if isinstance(misp, str):
        print('Cannot init MISP connection: {}'.format(misp))
        sys.exit(1)

    filename = args.file
    ip_column = args.ipcolumn
    cve_column = args.cvecolumn
    delimiter = args.delimiter

    data = load_file(filename, ip_column, cve_column, cve_pattern, delimiter)

    result = update_event_tags(data, misp)

    sys.exit(0)
