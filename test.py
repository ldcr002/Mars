#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import socket
import urlparse


def url2ip(url):
    '''
    Url to ip
    '''
    ip = ''
    try:
        url = url.strip()
        if not url.startswith("http"):
            url = add_protocal(url)
        handel_url = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(handel_url)
        # print ip
    except:
        print '[!] url2ip Can not get ip', url
        pass
    return ip


print(url2ip("www.baidu.com"))
