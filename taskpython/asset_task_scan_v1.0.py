#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 19/2/12 下午4:58
# @Author  : 重剑无锋
# @Site    : www.tidesec.com
# @Email   : 6295259@qq.com

import hashlib, json, time, requests, os
import random, ssl, socket, urllib
import subprocess
import threading, datetime, hackhttp, Queue
import xml.etree.cElementTree as ET
import sys, pymongo, re, urlparse
from bs4 import BeautifulSoup as BS
from qqwry import QQwry
import nmap

debug_mod = 1  # debug模式，0为关闭，1为开启

try:
    import requests
except:
    print 'pip install requests[security]'
    os._exit(0)

try:
    import lxml
except:
    print 'pip install lxml'
    os._exit(0)

try:
    import qqwry
except:
    print 'pip install qqwry-py2'
    os._exit(0)

try:
    import dns.resolver
except:
    print 'pip install dnspython'
    os._exit(0)

# Check py version
pyversion = sys.version.split()[0]
if pyversion >= "3" or pyversion < "2.7":
    exit('Need python version 2.6.x or 2.7.x')

reload(sys)
sys.setdefaultencoding('utf-8')

lock = threading.Lock()

global pwd, path

# Ignore warning
requests.packages.urllib3.disable_warnings()
# Ignore ssl warning info.
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

header_task = {
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Cookie': 'thinkphp_show_page_trace=0|0; thinkphp_show_page_trace=0|0; think_var=zh-cn; PHPSESSID=gljsd5c3ei5n813roo4878q203',
    'X-Requested-With': 'XMLHttpRequest'
}

MONGODB_CONFIG = {
    'host': '127.0.0.1',
    'port': 27017,
    'db_name': 'mars',
    'username': 'mars',
    'password': 'tidesec.com'
}


def requests_proxies():
    '''
    Proxies for every requests
    '''
    proxies = {
        'http': '',  # 127.0.0.1:1080 shadowsocks
        'https': ''  # 127.0.0.1:8080 BurpSuite
    }
    return proxies


def requests_headers():
    '''
    Random UA  for every requests && Use cookie to scan
    '''
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
                  'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60',
                  'Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
                  'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
                  'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
                  'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
                  'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UA, 'Upgrade-Insecure-Requests': '1', 'Connection': 'keep-alive', 'Cache-Control': 'max-age=0',
        'Accept-Encoding': 'gzip, deflate, sdch', 'Accept-Language': 'zh-CN,zh;q=0.8',
        "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com",
        'Cookie': "PHPSESSID=gljsd5c3ei5n813roo4878q203"}
    return headers













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


class Singleton(object):
    # 单例模式写法,参考：http://ghostfromheaven.iteye.com/blog/1562618
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, '_instance'):
            orig = super(Singleton, cls)
            cls._instance = orig.__new__(cls, *args, **kwargs)
        return cls._instance


class MongoConn(Singleton):
    """
    链接Mongodb数据库
    """
    def __init__(self):
        # connect db
        try:
            self.conn = pymongo.MongoClient(MONGODB_CONFIG['host'], MONGODB_CONFIG['port'])
            self.db = self.conn[MONGODB_CONFIG['db_name']]
            self.username = MONGODB_CONFIG['username']
            self.password = MONGODB_CONFIG['password']
            if self.username and self.password:
                self.connected = self.db.authenticate(self.username, self.password, mechanism="SCRAM-SHA-1")
                # self.db = self.conn[MONGODB_CONFIG['db_name']]  # connect db
            else:
                self.connected = self.db
        except Exception:
            print 'Connect Statics Database Fail.'
            # sys.exit(1)


def check_connected(conn):
    # 检查是否连接成功
    try:
        if not conn.connected:
            raise NameError, 'stat:connected Error'
    except Exception, e:
        now = time.strftime('%Y-%m-%d_%X', time.localtime(time.time()))
        info = '%s  Mongo Connect Error: %s' % (now, e)
        print info
        print "sleep 60s\n"
        time.sleep(60)
        print "Try to connect MongoDB:", MONGODB_CONFIG['host']
        my_conn = MongoConn()
        check_connected(my_conn)


def select_colum(table, value, colum):
    # 查询指定列的所有值
    try:
        # my_conn = MongoConn()
        # check_connected(my_conn)
        return my_conn.db[table].find(value, {colum: 1})
    except Exception:
        print 'stat:connected Error'


def insert_one(table, data):
    # 更新插入，根据‘ip’删除其他记录，如果‘ip’的值不存在，则插入一条记录
    try:
        # my_conn = MongoConn()
        # check_connected(my_conn)
        query = {'ip': data.get('ip', '')}
        if my_conn.db[table].find_one(query):
            my_conn.db[table].remove(query)
        my_conn.db[table].insert(data)
    except Exception, e:
        print "insert error:", e


def checkend(xmlfile):
    try:
        infile = open(xmlfile, 'r+')
        endxml = '''<runstats><finished time="1518405307" timestr="Sun Feb 11 22:15:07 2018" elapsed="396.80" summary="Nmap done at Sun Feb 11 22:15:07 2018; 256 IP addresses (136 hosts up) scanned in 396.80 seconds" exit="success"/><hosts up="136" down="120" total="256"/>
            </runstats>
            </nmaprun>'''
        x = infile.readlines()
        lens = len(x)
        if not x[lens - 3].startswith('<runstats>'):
            print xmlfile, " not endwith <runstats>"
            print '\n' * 3 + "Rstart python" + '\n' * 3
            restart_python = '. /root/tide/webscan/task.sh'
            os.system(restart_python)

            infile.write('\n')
            infile.write(endxml)
            infile.close()
            return "0"
        else:
            return "1"
    except:
        pass


def parse_xml(xmlfile):
    try:
        # outfile = open(ip_temp_db, 'a+')
        tree = ET.ElementTree(file=xmlfile)
        for elem in tree.iterfind('host'):
            if (elem[0].attrib['state']) == "up":
                is_up = "up"
            else:
                is_up = "down"
            ip = elem[1].attrib['addr']
            print ip
            scantime = elem.attrib['starttime']
            time_local = time.localtime(float(scantime))
            updatetime = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
            if elem[3].tag == 'hostnames':
                port_num = 4
            else:
                port_num = 3

            port_info = []
            if len(elem) > 3:
                ports = elem[port_num]
                for x in ports.iterfind('port'):
                    port = x.attrib['portid']
                    protocol = x.attrib['protocol']
                    state = x[0].attrib['state']
                    service = ''
                    product = ''
                    product_ver = ''
                    extrainfo = ''
                    banner_brief = ''
                    banner_info = ''
                    site_info = ''
                    trap_flag = 1

                    if (state == 'open'):
                        url = ip + ":" + port
                        if (len(x) > 1):
                            if 'name' in x[1].keys():
                                service = x[1].attrib['name']

                            if 'product' in x[1].keys():
                                product = x[1].attrib['product']

                            if 'version' in x[1].keys():
                                product_ver = x[1].attrib['version']

                            if 'extrainfo' in x[1].keys():
                                extrainfo = x[1].attrib['extrainfo']

                            if 'ostype' in x[1].keys():
                                extrainfo = x[1].attrib['ostype']

                            if (len(x) > 2) and ('output' in x[2].keys()):
                                banner_brief = x[2].attrib['output']
                                banner_brief = banner_brief.decode('utf-8', 'ignore').encode('utf-8')
                            if (service == 'tcpwrapped'):
                                trap_flag = 0

                            # if ('http' in service):
                            #     site_info = get_header(url)
                            #     print "111"
                            #     if site_info:
                            #         banner_info = site_info

                        if trap_flag:
                            port_data = {'port': port, 'protocol': protocol, 'state': state,
                                         'service': service, 'product': product, 'banner_brief': banner_brief,
                                         'extrainfo': extrainfo, 'product_ver': product_ver, 'banner_info': banner_info}
                            port_info.append(port_data)

            os = elem[port_num + 1]
            os_info = ''
            print "222"

            if len(os) > 0:
                for x in os.iterfind('osmatch'):
                    os_info = x.attrib['name']
                    break

            hostnames = elem[port_num - 1]
            hostname_info = ''
            if len(hostnames) > 0:
                for x in hostnames.iterfind('hostname'):
                    hostname_info = x.attrib['name']
                    break

            ip_info = getipinfo(ip)
            print "333"

            ip_data = {'ip': ip, 'updatetime': updatetime, 'ip_info': ip_info, 'is_up': is_up,
                       'os': os_info, 'hostname': hostname_info,
                       'port_info': port_info}

            print xmlfile, " current ip:", ip

            return ip_data

    except Exception, e:
        now = time.strftime('%Y-%m-%d_%X', time.localtime(time.time()))
        info = '\033[1;35m[!] %s\nParse_xml Error: %s \033[0m!' % (now, e)
        print info














def md5hash(ip):
    md5 = hashlib.md5()
    md5.update(ip)
    return md5.hexdigest()


class Worker(threading.Thread):  # 处理工作请求
    def __init__(self, workQueue, resultQueue, **kwds):
        threading.Thread.__init__(self, **kwds)
        self.setDaemon(True)
        self.workQueue = workQueue
        self.resultQueue = resultQueue

    def run(self):
        while 1:
            try:
                callable, args, kwds = self.workQueue.get(False)  # get task
                res = callable(*args, **kwds)
                self.resultQueue.put(res)  # put result
            except Queue.Empty:
                break


class WorkManager:  # 线程池管理,创建
    def __init__(self, num_of_workers=10):
        self.workQueue = Queue.Queue()  # 请求队列
        self.resultQueue = Queue.Queue()  # 输出结果的队列
        self.workers = []
        self._recruitThreads(num_of_workers)

    def _recruitThreads(self, num_of_workers):
        for i in range(num_of_workers):
            worker = Worker(self.workQueue, self.resultQueue)  # 创建工作线程
            self.workers.append(worker)  # 加入到线程队列

    def start(self):
        for w in self.workers:
            w.start()

    def wait_for_complete(self):
        while len(self.workers):
            worker = self.workers.pop()  # 从池中取出一个线程处理请求
            worker.join()
            if worker.isAlive() and not self.workQueue.empty():
                self.workers.append(worker)  # 重新加入线程池中

    def add_job(self, callable, *args, **kwds):
        self.workQueue.put((callable, args, kwds))  # 向工作队列中加入请求

    def get_result(self, *args, **kwds):
        return self.resultQueue.get(*args, **kwds)














def connect_port(ip, port):
    global open_port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            print '[+] ', port, 'open'
            open_port.append(port)
    except:
        pass












def port_scanner(host, target, ip_range, port_range):
    result = []
    ports = []
    try:
        scanner = nmap.PortScanner()
        if not host:
            host = url2ip(target)
        if host:
            traget_open_port, ipaddr = scan_c_port(host, 1, 1)  # ip地址，1=扫描单个ip 2=扫描c段，1=全端口扫描 2=部分端口扫描
            updatetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            if len(traget_open_port.split(',')) > 100:
                traget_open_port = '21,22,23,80,81,443,554,1080,1433,1900,3306,3389,7547,8080,8081,8082'
            if traget_open_port:
                arguments = "-sT -sV -sC -A -Pn -O --open -p " + traget_open_port
                print "Nmap Scaning: nmap ", arguments, ' ', host
                # port processing
                scanner.scan(host, arguments=arguments)
                # port 'state' == 'open'
                print("Scanning: %s" % host)

                os = ''
                for osmatch in scanner[host]['osmatch']:
                    os = osmatch['name']
                    break

                for port in scanner[host].all_tcp():
                    if scanner[host]['tcp'][port]['state'] == 'open':
                        if "script" in scanner[host]['tcp'][port].keys():
                            script = scanner[host]['tcp'][port]['script']
                            if script.has_key('http-robots.txt'):
                                script['http-robots_txt'] = script['http-robots.txt']
                                del script['http-robots.txt']
                        else:
                            script = ''
                        if len(scanner[host]['tcp'][port]['version']) > 0:
                            version = scanner[host]['tcp'][port]['version']
                        else:
                            version = 'Unknown'
                        if len(scanner[host]['tcp'][port]['product']) > 0:
                            product = scanner[host]['tcp'][port]['product']
                        else:
                            product = scanner[host]['tcp'][port]['name']
                        data = {
                            "product": product,
                            "version": version,
                            "name": scanner[host]['tcp'][port]['name'],
                            "script": script,
                            "extrainfo": scanner[host]['tcp'][port]['extrainfo'],
                            "cpe": scanner[host]['tcp'][port]['cpe'],
                            "host": host,
                            "port": port,
                            "updatetime": updatetime
                        }
                        ports.append(port)
                        result.append(data)
                return result, os, ports
    except Exception as msg:
        print(msg)
        pass
    return result, '', ports


def bugscan_cms(url, log):
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
               "Referer": "http://whatweb.bugscaner.com/look/",
               }
    """
    try:
        res = requests.get('http://whatweb.bugscaner.com/look/',timeout=60, verify=False)
        if res.status_code==200:
            hashes = re.findall(r'value="(.*?)" name="hash" id="hash"',res.content)[0]
    except Exception as e:
        print str(e)
        return False
    """
    data = "url=%s&hash=0eca8914342fc63f5a2ef5246b7a3b14_7289fd8cf7f420f594ac165e475f1479" % (url)
    try:
        respone = requests.post("http://whatweb.bugscaner.com/what/", data=data, headers=headers, timeout=60,
                                verify=False)
        if int(respone.status_code) == 200:
            pattern1 = re.compile('.*?CMS": (.*?),')

            cms = re.findall(pattern1, respone.content)

            result = json.loads(respone.content)
            if len(result["CMS"]) > 0:
                # out.write(result["cms"].strip())
                return result["CMS"]
            else:
                return ''

    except Exception as e:
        print "bugscan_cms:", str(e)
        # out.write('Unknown')
        return ''


def check_info_changed(old_data, webinfo):
    try:

        info_changed = 0
        ip_changed = []
        title_changed = []
        if old_data.has_key('scan_times'):
            webinfo['scan_times'] = old_data['scan_times'] + 1
        else:
            webinfo['scan_times'] = 1

        if old_data:
            # print "old_data",old_data
            if old_data['ip'] != webinfo['ip']:
                if old_data.has_key('ip_changed'):
                    ip_changed = old_data['ip_changed']
                ip_changed.append(
                    str(old_data['ip']) + '||' + str(old_data['title']) + '||' + str(old_data['ports']) + '||' + str(
                        old_data['updatetime']))
                webinfo['ip_changed'] = ip_changed

            if old_data['title'] != webinfo['title']:
                if old_data.has_key('title_changed'):
                    title_changed = old_data['title_changed']
                title_changed.append(
                    str(old_data['ip']) + '||' + str(old_data['title']) + '||' + str(old_data['ports']) + '||' + str(
                        old_data['updatetime']))
                webinfo['title_changed'] = title_changed

            if webinfo['ports'] != old_data[
                'ports']:  # 如果本次扫描的端口和上次不同，则创建新的port_info，从新数据到旧数据依次为port_info、port_info_2、port_info_3
                if old_data.has_key('port_info_2'):
                    webinfo['port_info_3'] = old_data['port_info_2']
                    webinfo['ports_3'] = old_data['ports_2']
                    webinfo['port_info_2'] = old_data['port_info']
                    webinfo['ports_2'] = old_data['ports']
                else:
                    webinfo['port_info_2'] = old_data['port_info']
                    webinfo['ports_2'] = old_data['ports']

            for port_tmp in webinfo['ports']:
                if port_tmp not in old_data['ports']:
                    info_changed = 1
                    print "waring:", port_tmp
                    break
            if title_changed or ip_changed:
                info_changed = 1

        if info_changed:
            webinfo['info_changed'] = '1'

        return webinfo
    except Exception, e:
        print "\033[1;35m[!] check_info_changed error :\033[0m!", e
        return webinfo


class TimeoutError(Exception):
    pass


def run_check_cdn(cmd, timeout=60):
    try:
        p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
        t_beginning = time.time()
        seconds_passed = 0
        while True:
            if p.poll() is not None:
                break
            seconds_passed = time.time() - t_beginning
            if timeout and seconds_passed > timeout:
                p.terminate()
                raise TimeoutError(cmd, timeout)
            time.sleep(0.1)
        return p.stdout.read()
    except:
        pass






def get_host_info():
    try:
        hostname = socket.gethostname()
    except:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('114.114.114.114', 80))
        ip = s.getsockname()[0]
        hostname = ip
        s.close()
    return hostname


def get_nmap_target(target):
    url = target
    if url[0:4] == 'http':
        proto, rest = urllib.splittype(url)
        host, rest = urllib.splithost(rest)
    else:
        host = url
    if ':' in host:
        host = host.split(':')[0]
    if '/' in host:
        host = host.split('/')[0]
    return host


def get_domain(target):
    try:
        url = target
        if url[0:4] == 'http':
            proto, rest = urllib.splittype(url)
            host, rest = urllib.splithost(rest)
            if host[0:3] == 'www':
                host = host[4:]
        elif url[0:3] == 'www':
            host = url[4:]
        else:
            host = url
        if ':' in host:
            host = host.split(':')[0]
        if '/' in host:
            host = host.split('/')[0]

        return host
    except:
        return target


def get_main_domain(domain):
    double_exts = ['.com.cn', '.edu.cn', '.gov.cn', '.org.cn', '.net.cn']

    main_domain = domain

    for ext in double_exts:
        if ext in domain:
            if len(domain.split('.')) > 3:
                # print "yuanshi",domain
                domain_split = domain.split('.')
                domain_new = "%s.%s.%s" % (domain_split[-3], domain_split[-2], domain_split[-1])
                # print "exact",domain
                main_domain = domain_new
            else:
                main_domain = domain

            break
        else:
            if len(domain.split('.')) > 2:
                domain_split = domain.split('.')
                domain_new = "%s.%s" % (domain_split[-2], domain_split[-1])
                main_domain = domain_new
            else:
                main_domain = domain
    return main_domain


def ip_regex(raw):
    try:
        re_ips = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', str(raw))
        if re_ips:
            return True
        else:
            return False
    except Exception, e:
        print e
        return False


def set_dirs(domain):
    global pwd, path
    path = pwd + '/libs/'
    daytime = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    logpath = pwd + '/log/' + daytime + '/' + domain + '/'

    try:
        if not os.path.exists(logpath):
            os.makedirs(logpath, 0755)
        if not os.path.exists(pwd + '/log/loginfo/'):
            os.makedirs(pwd + '/log/loginfo/', 0755)
        if not os.path.exists(logpath + 'temp/'):
            os.makedirs(logpath + 'temp/', 0755)
        if not os.path.exists(logpath + 'domain/'):
            os.makedirs(logpath + 'domain/', 0755)
        return logpath
    except Exception, e:
        print "\033[1;35m[!] Set Dirs Error \033[0m!", e
        return logpath


def add_protocal(sub_target):
    sub_target_tmp = sub_target
    try:
        if not sub_target.startswith("http"):
            sub_target_tmp = "http://" + sub_target
        res = requests.get(url=sub_target_tmp, timeout=10, verify=False)
        return sub_target_tmp
    except:
        try:
            if not sub_target.startswith("http"):
                sub_target_tmp = "https://" + sub_target
            res = requests.get(url=sub_target_tmp, timeout=10, verify=False)
            return sub_target_tmp
        except:
            return "http://" + sub_target




def domain_task(main_domain, task_sub_domain, task):
    try:
        wm_domain_task = WorkManager(10)

        if task.has_key('scan_times'):
            scan_times = task['scan_times'] + 1
        else:
            scan_times = 1

        if ip_regex(main_domain):
            ipaddl = main_domain.split('.')
            ipaddr_path = ipaddl[0] + '_' + ipaddl[1] + '_' + ipaddl[2] + '_1'
            logpath = set_dirs(ipaddr_path)
            ipaddr = ipaddrs(main_domain)

            # print ipaddr
            ip_up_addrs = up_host_scan(ipaddr)
            # ip_up_addrs= ['123.134.184.189']
            # print ip_up_addrs
            for ip in ip_up_addrs:
                print "get_c_info:", ip
                wm_domain_task.add_job(get_c_info, main_domain, ip, logpath, task)
                # get_c_info(main_domain,ip,logpath,task)
                # exit(0)
            wm_domain_task.start()
            wm_domain_task.wait_for_complete()
            # print "c_scan"
            updatetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            my_conn.db[mongo_asset_db].update({'_id': task['_id']}, {
                "$set": {"task_state": "ok", "updatetime": updatetime, "scan_times": scan_times}}, False, False)

        else:
            if main_domain == 'other_host':
                logpath = set_dirs(main_domain)
                for task_sub_url in task_sub_domain:
                    task_sub_url = task_sub_url.strip()
                    sub_domain = get_domain(task_sub_url)
                    sub_target = add_protocal(task_sub_url)
                    wm_domain_task.add_job(get_domain_info, sub_domain, sub_target, logpath, task)
                wm_domain_task.start()
                wm_domain_task.wait_for_complete()
            else:
                all_targets, logpath, server_tmp = task_subdomain(main_domain, task_sub_domain)

                print "all_targets:", all_targets
                logpath = set_dirs(main_domain)

                for sub_target in all_targets:
                    sub_domain = sub_target.strip()
                    sub_target = add_protocal(sub_domain)
                    print sub_target
                    wm_domain_task.add_job(get_domain_info, sub_domain, sub_target, logpath, task)
                    # get_domain_info(sub_domain, sub_target, logpath,task)
                wm_domain_task.start()
                wm_domain_task.wait_for_complete()

            updatetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            my_conn.db[mongo_asset_db].update({'_id': task['_id']}, {
                "$set": {"task_state": "ok", "updatetime": updatetime, "scan_times": scan_times}}, False, False)
            if task.has_key('c_scan'):
                if task['c_scan'] == 'Enable':
                    insert_new_c_asset_task(task)

    except Exception, e:
        print "\033[1;35m[!] domain_task error,\033[0m!", e


def mongo_task_get(task_num):
    task_ing_num = my_conn.db[mongo_asset_db].find({'task_state': 'ing', 'scan_node': scan_node}).count()
    print "task_ing_num", task_ing_num
    if task_ing_num > 0:
        task_datas = []
        task_ing_datas = my_conn.db[mongo_asset_db].find({'task_state': 'ing', 'scan_node': scan_node}).sort(
            'asset_date', 1).limit(task_ing_num)

        if task_ing_num < task_num:
            task_new_num = my_conn.db[mongo_asset_db].find({'task_state': 'new', 'discover_option': 'Enable'}).sort(
                'asset_date', 1).count()
            print "task_new_num", task_new_num
            if task_new_num > 0:
                task_new_datas = my_conn.db[mongo_asset_db].find(
                    {'task_state': 'new', 'discover_option': 'Enable'}).sort('asset_date', 1).limit(
                    task_num - task_ing_num)
                for task_tmp_2 in task_new_datas:
                    task_datas.append(task_tmp_2)
        for task_tmp_1 in task_ing_datas:
            task_datas.append(task_tmp_1)
        return task_datas
    else:
        task_new_num = my_conn.db[mongo_asset_db].find({'task_state': 'new', 'discover_option': 'Enable'}).sort(
            'asset_date', 1).count()
        print "task_new_num", task_new_num
        if task_new_num > 0:
            task_datas = my_conn.db[mongo_asset_db].find({'task_state': 'new', 'discover_option': 'Enable'}).sort(
                'asset_date', 1).limit(task_num)
            return task_datas
        else:
            task_datas = my_conn.db[mongo_asset_db].find({'task_state': 'ok', 'discover_option': 'Enable'}).sort(
                'scan_times', 1)

            now = time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
            new_tasks = []

            for task in task_datas:
                jiange = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') - datetime.datetime.strptime(
                    task['updatetime'], '%Y-%m-%d %H:%M:%S')
                if int(task['asset_scan_zhouqi']) == 0:
                    continue
                elif jiange.days >= int(task['asset_scan_zhouqi']):
                    new_tasks.append(task)
                    break
            return new_tasks


run_month = time.strftime('%m', time.localtime(time.time()))
run_day = time.strftime('%d', time.localtime(time.time()))

port = [1, 11, 13, 15, 17, 19, 21, 22, 23, 25, 26, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 43, 53, 69, 70, 79, 80, 81,
        82, 83, 84, 85, 88, 98, 100, 102, 110, 111, 113, 119, 123, 135, 137, 139, 143, 161, 179, 199, 214, 264, 280,
        322, 389, 407, 443, 444, 445, 449, 465, 497, 500, 502, 505, 510, 514, 515, 517, 518, 523, 540, 548, 554, 587,
        591, 616, 620, 623, 626, 628, 631, 636, 666, 731, 771, 782, 783, 789, 873, 888, 898, 900, 901, 902, 989, 990,
        992, 993, 994, 995, 1000, 1001, 1010, 1022, 1023, 1026, 1040, 1041, 1042, 1043, 1080, 1091, 1098, 1099, 1200,
        1212, 1214, 1220, 1234, 1241, 1248, 1302, 1311, 1314, 1344, 1400, 1419, 1432, 1434, 1443, 1467, 1471, 1501,
        1503, 1505, 1521, 1604, 1610, 1611, 1666, 1687, 1688, 1720, 1723, 1830, 1900, 1901, 1911, 1947, 1962, 1967,
        2000, 2001, 2002, 2010, 2024, 2030, 2048, 2051, 2052, 2055, 2064, 2080, 2082, 2083, 2086, 2087, 2160, 2181,
        2222, 2252, 2306, 2323, 2332, 2375, 2376, 2396, 2404, 2406, 2427, 2443, 2455, 2480, 2525, 2600, 2628, 2715,
        2869, 2967, 3000, 3002, 3005, 3052, 3075, 3128, 3280, 3306, 3310, 3333, 3372, 3388, 3389, 3443, 3478, 3531,
        3689, 3774, 3790, 3872, 3940, 4000, 4022, 4040, 4045, 4155, 4300, 4369, 4433, 4443, 4444, 4567, 4660, 4711,
        4848, 4911, 5000, 5001, 5007, 5009, 5038, 5050, 5051, 5060, 5061, 5222, 5269, 5280, 5357, 5400, 5427, 5432,
        5443, 5550, 5555, 5560, 5570, 5598, 5601, 5632, 5800, 5801, 5802, 5803, 5820, 5900, 5901, 5902, 5984, 5985,
        5986, 6000, 6060, 6061, 6080, 6103, 6112, 6346, 6379, 6432, 6443, 6544, 6600, 6666, 6667, 6668, 6669, 6670,
        6679, 6697, 6699, 6779, 6780, 6782, 6969, 7000, 7001, 7002, 7007, 7070, 7077, 7100, 7144, 7145, 7180, 7187,
        7199, 7200, 7210, 7272, 7402, 7443, 7479, 7547, 7776, 7777, 7780, 8000, 8001, 8002, 8003, 8004, 8005, 8006,
        8007, 8008, 8009, 8010, 8025, 8030, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088,
        8089, 8090, 8098, 8112, 8118, 8129, 8138, 8181, 8182, 8194, 8333, 8351, 8443, 8480, 8500, 8529, 8554, 8649,
        8765, 8834, 8880, 8881, 8882, 8883, 8884, 8885, 8886, 8887, 8888, 8890, 8899, 8983, 9000, 9001, 9002, 9003,
        9030, 9050, 9051, 9080, 9083, 9090, 9091, 9100, 9151, 9191, 9200, 9292, 9300, 9333, 9334, 9443, 9527, 9595,
        9600, 9801, 9864, 9870, 9876, 9943, 9944, 9981, 9997, 9999, 10000, 10001, 10005, 10030, 10035, 10080, 10243,
        10443, 11000, 11211, 11371, 11965, 12000, 12203, 12345, 12999, 13013, 13666, 13720, 13722, 14000, 14443, 14534,
        15000, 15001, 15002, 16000, 16010, 16922, 16923, 16992, 16993, 17988, 18080, 18086, 18264, 19150, 19888, 19999,
        20000, 20547, 23023, 25000, 25010, 25020, 25565, 26214, 26470, 27015, 27017, 27960, 28006, 28017, 29999, 30444,
        31337, 31416, 32400, 32750, 32751, 32752, 32753, 32754, 32755, 32756, 32757, 32758, 32759, 32760, 32761, 32762,
        32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
        32779, 32780, 32781, 32782, 32783, 32784, 32785, 32786, 32787, 32788, 32789, 32790, 32791, 32792, 32793, 32794,
        32795, 32796, 32797, 32798, 32799, 32800, 32801, 32802, 32803, 32804, 32805, 32806, 32807, 32808, 32809, 32810,
        34012, 34567, 34599, 37215, 37777, 38978, 40000, 40001, 40193, 44443, 44818, 47808, 49152, 49153, 50000, 50030,
        50060, 50070, 50075, 50090, 50095, 50100, 50111, 50200, 52869, 5341, 55555, 56667, 60010, 60030, 60443, 61616,
        64210, 64738, 4768]

# port =[80,443,843,8080,18556,19359]

log = open('losg.txt', 'a+')
scan_node = get_host_info()
lock = threading.Lock()
# host_info = 'tide120'
print "scan_node:", scan_node

task_num = 5
scan_thread = 5000

mongo_asset_db = 'dev_asset'
mongo_server_db = 'dev_server'

pwd = os.getcwd()

if __name__ == "__main__":
    now = time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
    while True:
        try:
            my_conn = MongoConn()
            check_connected(my_conn)
            start = datetime.datetime.now()
            pwd = os.getcwd()

            now_day = time.strftime('%d', time.localtime(time.time()))

            targets = []
            task_datas = mongo_task_get(task_num)
            domain_thread = []
            wm = WorkManager(5)
            # exit(0)

            if task_datas:
                for task in task_datas:
                    if task:
                        print task
                        if task['task_state'] == 'new':
                            my_conn.db[mongo_asset_db].update({'_id': task['_id']},
                                                              {"$set": {"task_state": "ing", 'scan_node': scan_node}},
                                                              False, False)

                        main_domain = task['asset_name']
                        task_sub_domain = task['asset_host']
                        wm.add_job(domain_task, main_domain, task_sub_domain, task)

                wm.start()
                wm.wait_for_complete()

            end = datetime.datetime.now()
            print "starttime:", start
            print "endtime:", end
            print "time_use:", (end - start).seconds
            time.sleep(300)
            # exit(0)
        except Exception, e:
            info = '\033[1;35m[!]%s\n Main_function Error: %s\033[0m!' % (now, e)
            print info
