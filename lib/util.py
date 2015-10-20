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


from dateutil.tz import tzutc
import datetime
import pytz


def nowutc():
    '''utc now'''
    return datetime.datetime.utcnow().replace(tzinfo=pytz.utc)


def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)
