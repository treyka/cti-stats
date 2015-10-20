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


def process_taxii_content_blocks(content_block):
    '''process taxii content blocks'''
    incidents = dict()
    indicators = dict()
    observables = dict()
    xml = StringIO.StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
    # if stix_package.incidents:
    #     for j in stix_package.incidents:
    #         incidents[j.id_] = j
    # if stix_package.indicators:
    #     for i in stix_package.indicators:
    #         indicators[i.id_] = i
    # if stix_package.observables:
    #     for o in stix_package.observables.observables:
    #         observables[o.id_] = o
    # return(incidents, indicators, observables)


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
        import pudb; pu.db
        pass
        # incidents = dict()
        # indicators = dict()
        # observables = dict()
        # for content_block in taxii_message.content_blocks:
        #     (incidents_, indicators_, observables_) = \
        #         process_taxii_content_blocks(config, content_block)
        #     incidents.update(incidents_)
        #     indicators.update(indicators_)
        #     observables.update(observables_)
        return(latest, incidents, indicators, observables)
