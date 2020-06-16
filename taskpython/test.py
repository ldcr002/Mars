#!/usr/bin/env python
# -*- coding: utf-8 -*-

def get_header(url):
    try:
        print "Get http header:", url
        url = add_protocal(url)
        hh = hackhttp.hackhttp()
        code, head, body, redirect, log = hh.http(url, headers=requests_headers())
        print "Get header ok:", url
        if log:
            return log['response'].decode('utf-8', 'ignore').encode('utf-8')
        else:
            return False
    except:
        return False