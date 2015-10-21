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
from util import epoch_start, nowutc
from StringIO import StringIO


def process_taxii_content_blocks(content_block):
    '''process taxii content blocks'''
    incidents = dict()
    indicators = dict()
    observables = dict()
    xml = StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
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
    '''pull cti via taxii'''
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
            (raw_stix_objs, raw_cybox_objs) = \
                process_taxii_content_blocks(content_block)
            for k in raw_stix_objs.keys():
                cooked_stix_objs[k].update(raw_stix_objs[k])
            for k in raw_cybox_objs.keys():
                if not k in cooked_cybox_objs.keys():
                    cooked_cybox_objs[k] = set()
                cooked_cybox_objs[k].update(raw_cybox_objs[k])
        return(cooked_stix_objs, cooked_cybox_objs)
