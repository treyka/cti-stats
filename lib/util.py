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
import time
import pytz
import os
import fnmatch


def nowutc():
    '''utc now'''
    return int(time.mktime(datetime.datetime.utcnow().replace(tzinfo=pytz.utc).timetuple()))


def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)


def poll_start():
    '''for an all-time poll, rather than starting at the epoch start,
    given that the STIX 1.0 release was tagged on Github 10.04.2013,
    assuming a start time of 01.01.2013 seems reasonable'''
    timestamp = datetime.datetime.strptime('01.01.2013 00:00:00 UTC', '%d.%m.%Y %H:%M:%S %Z')
    return int(time.mktime(timestamp.timetuple()))


def gen_find(pattern, top):
    '''A function that generates files that match a given filename pattern
    [with thanks/apologies to David Beazley for inspiration => http://www.dabeaz.com/generators-uk/genfind.py]'''
    for path, dirlist, filelist in os.walk(top):
        for name in fnmatch.filter(dirlist, pattern):
            yield os.path.join(path,name)
        for name in fnmatch.filter(filelist, pattern):
            yield os.path.join(path,name)


def resolve_path(dir):
    '''checks whether path starts with '~', if so resolves to full path, returns resolved path'''
    return os.path.expanduser(dir)
