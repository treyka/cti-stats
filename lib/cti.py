#!/usr/bin/env python


# Copyright 2015 Soltra Solutions, LLC
#
# Licensed under the Soltra License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.soltra.com/licenses/license-2.0.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.


from libtaxii.constants import *
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_10 as tm10
import libtaxii.messages_11 as tm11
from stix.core import STIXPackage
from util import epoch_start, nowutc, gen_find, resolve_path
from StringIO import StringIO



def taxii_content_block_to_stix(content_block):
    '''transform taxii content blocks into stix packages'''
    xml = StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
    return stix_package


def file_to_stix(file_):
    '''transform files into stix packages'''
    return STIXPackage.from_xml(file_)


def process_stix_pkg(stix_package):
    '''process stix packages'''
    incidents = dict()
    indicators = dict()
    observables = dict()
    raw_stix_objs = {'campaigns': set(), 'courses_of_action': set(), \
                        'exploit_targets': set(), 'incidents': set(), \
                        'indicators': set(), 'threat_actors': set(), \
                        'ttps': set()}
    raw_cybox_objs = dict()
    for k in raw_stix_objs.keys():
        for i in getattr(stix_package, k):
            raw_stix_objs[k].add(i.id_)
            if k == 'indicators' and len(i.observables):
                for j in i.observables:
                    if j.idref:
                        next
                    else:
                        obs_type = str(type(j.object_.properties)).split('.')[-1:][0].split("'")[0]
                        if not obs_type in raw_cybox_objs.keys():
                            raw_cybox_objs[obs_type] = set()
                        raw_cybox_objs[obs_type].add(j.id_)
    if stix_package.observables:
        for i in stix_package.observables:
            if i.idref:
                next
            else:
                obs_type = str(type(i.object_.properties)).split('.')[-1:][0].split("'")[0]
                if not obs_type in raw_cybox_objs.keys():
                    raw_cybox_objs[obs_type] = set()
                raw_cybox_objs[obs_type].add(i.id_)
    return(raw_stix_objs, raw_cybox_objs)


def taxii_poll(host=None, port=None, endpoint=None, collection=None, user=None, passwd=None, use_ssl=None, attempt_validation=None):
    '''poll cti via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(use_ssl)
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials(
        {'username': user,
         'password': passwd})
    earliest = epoch_start()
    latest = nowutc()
    poll_request = tm10.PollRequest(
       message_id=tm10.generate_message_id(),
        feed_name=collection,
        exclusive_begin_timestamp_label=earliest,
        inclusive_end_timestamp_label=latest,
        content_bindings=[t.CB_STIX_XML_11])
    http_response = client.callTaxiiService2(
        host, endpoint,
        t.VID_TAXII_XML_10, poll_request.to_xml(),
        port=port)
    taxii_message = t.get_message_from_http_response(http_response,
                                                     poll_request.message_id)
    if isinstance(taxii_message, tm10.StatusMessage):
        print('''TAXII connection error! Exiting...
%s''' % (taxii_message.message))
    elif isinstance(taxii_message, tm10.PollResponse):
        cooked_stix_objs = {'campaigns': set(), 'courses_of_action': set(), \
                     'exploit_targets': set(), 'incidents': set(), \
                     'indicators': set(), 'threat_actors': set(), \
                     'ttps': set()}
        cooked_cybox_objs = dict()
        for content_block in taxii_message.content_blocks:
            stix_package = taxii_content_block_to_stix(content_block)
            (raw_stix_objs, raw_cybox_objs) = \
                process_stix_pkg(stix_package)
            for k in raw_stix_objs.keys():
                cooked_stix_objs[k].update(raw_stix_objs[k])
            for k in raw_cybox_objs.keys():
                if not k in cooked_cybox_objs.keys():
                    cooked_cybox_objs[k] = set()
                cooked_cybox_objs[k].update(raw_cybox_objs[k])
        return(cooked_stix_objs, cooked_cybox_objs)


def dir_walk(target_dir):
    '''recursively walk a directory containing cti and return the stats'''
    files = gen_find('*.xml', resolve_path(target_dir))
    cooked_stix_objs = {'campaigns': set(), 'courses_of_action': set(), \
                        'exploit_targets': set(), 'incidents': set(), \
                        'indicators': set(), 'threat_actors': set(), \
                        'ttps': set()}
    cooked_cybox_objs = dict()
    for file_ in files:
        try:
            stix_package = file_to_stix(file_)
            (raw_stix_objs, raw_cybox_objs) = \
                process_stix_pkg(stix_package)
            for k in raw_stix_objs.keys():
                cooked_stix_objs[k].update(raw_stix_objs[k])
            for k in raw_cybox_objs.keys():
                if not k in cooked_cybox_objs.keys():
                    cooked_cybox_objs[k] = set()
                cooked_cybox_objs[k].update(raw_cybox_objs[k])
        except:
            next
    return (cooked_stix_objs, cooked_cybox_objs)


def print_stats(cooked_stix_objs, cooked_cybox_objs):
    '''print cti stats'''
    print('+-------STIX stats------------------------------------------------------+')
    stix_total = 0
    for k in cooked_stix_objs.keys():
        stix_total += len(cooked_stix_objs[k])
    print('+-------STIX percentages------------------------------------------------+')
    for k in cooked_stix_objs.keys():
        if len(cooked_stix_objs[k]):
            print("%s: %s" % (k, '{1:.{0}f}%'.format(2, (float(len(cooked_stix_objs[k]) * 100) / float(stix_total)))))
    print('+-------STIX counts-----------------------------------------------------+')
    for k in cooked_stix_objs.keys():
        if len(cooked_stix_objs[k]):
            print("%s: %i" % (k, len(cooked_stix_objs[k])))
    print("Total STIX objects: %i" % (stix_total))
    print('')
    print('+-------CybOX stats-----------------------------------------------------+')
    cybox_total = 0
    for k in cooked_cybox_objs.keys():
        cybox_total += len(cooked_cybox_objs[k])
    print('+-------CybOX percentages-----------------------------------------------+')
    for k in cooked_cybox_objs.keys():
        if len(cooked_cybox_objs[k]):
            print("%s: %s" % (k, '{1:.{0}f}%'.format(2, (float(len(cooked_cybox_objs[k]) * 100) / float(cybox_total)))))
    print('+-------CybOX counts----------------------------------------------------+')
    for k in cooked_cybox_objs.keys():
        if len(cooked_cybox_objs[k]):
            print("%s: %i" % (k, len(cooked_cybox_objs[k])))
    print("Total CybOX objects: %i" % (cybox_total))
