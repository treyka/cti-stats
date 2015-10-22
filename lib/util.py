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
import os
import fnmatch


def nowutc():
    '''utc now'''
    return datetime.datetime.utcnow().replace(tzinfo=pytz.utc)


def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)


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
