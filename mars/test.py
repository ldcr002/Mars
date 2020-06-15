#!/usr/bin/env python
# -*- coding: utf-8 -*-

asset_host = "127.0.0.1"
asset_host = asset_host.replace('\r', '').split('\n', -1)  # 返回元组([u'www.vbboy.com', u'demo.tidesec.net', u'http://www.tidesec.net', u'192.168.1.1/24'],)
print asset_host