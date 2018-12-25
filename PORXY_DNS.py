#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/3/15 17:49
# @Author  : qiusong_chen@foxmail.com
# @Site    :
# @File    : dnsPorxy.py
# @Software: PyCharm

import ConfigParser
import SocketServer
import socket
import base64
import dnslib
import redis
import re
import os
import sys
import gevent
import pickle
from gevent import monkey
from datetime import datetime
from dns import resolver

monkey.patch_all()
from gevent.queue import Queue
import pylru

def debug_(content):
    if debug:
        print content

def gfw_q(name):
    return re.findall(name, gfwlist)

def forward_q(name):
    return re.findall(name, forwardlist)

def whitelist_q(name):
    return re.findall(name, whitelist)

class RedisHandler:
    def __init__(self, host, port, name, passwd):
        self.host = host
        self.port = port
        self.name = name
        self.passwd = passwd
        if not hasattr(RedisHandler, 'pool'):
            RedisHandler.create_pool(self.host, self.port, self.passwd)
        self._connection = redis.Redis(connection_pool =  RedisHandler.pool)

    @staticmethod
    def create_pool(HOST,PORT,PASSWD):
        RedisHandler.pool = redis.ConnectionPool(host = HOST, port = PORT, password=PASSWD)

    def r_get(self):
        tmp = self._connection.get(self.name)
        if tmp:
            return pickle.loads(tmp)
        else:
            return None
    def r_set(self, key, value, redis_expire):
        self._connection.set(key, pickle.dumps(value))
        self._connection.expire(key, redis_expire)

    def delete(self, key):
        self._connection.delete(*self._connection.keys(key))

def handler(data, client, sock):
    try:
        request = dnslib.DNSRecord.parse(data)

        qname = request.q.qname
        q_name_list = str(qname).split('.')
        q_name = ".".join(q_name_list[-3:len(q_name_list)-1])
        q_domain = ".".join(q_name_list[:len(q_name_list)-1])
        qid = request.header.id
        qtype = request.q.qtype
        qt = dnslib.QTYPE[qtype]
        redis_key = "%s_%s" %(qt, qname)
        r_handler = RedisHandler(redis_ip, redis_port, redis_key, passwd)
        r_get = r_handler.r_get()
        msg = "############### %s request domain is %s   ###############" % (client, q_domain)

    except Exception as e:
        print 'Not a DNS packet.\n', e
        return

    else:
        if str(qname)[:-1] in cnamelist:
            cname_v = cnamelist[str(qname)[:-1]]
            cname = "%s %s IN CNAME %s" % (str(qname)[:-1], ttl, cnamelist[str(qname)[:-1]])
            reply = request.replyZone(cname)
            ans = resolver.query(cname_v, "A")
            for i in ans.response.answer:
                i_list = i.to_text().split("\n")
                for k in i_list:
                    ip = k.split(" ")[-1]
                    reply.add_answer(dnslib.RR(cname_v,dnslib.QTYPE.A,rdata=dnslib.A(ip),ttl=ttl))
            sock.sendto(reply.pack(), client)
            debug_(msg)
            debug_(reply)
            return

        if str(qname)[:-1] in aList:
            ip = aList[str(qname)[:-1]]
            answer = request.reply()
            answer.add_answer(dnslib.RR(qname, dnslib.QTYPE.A, rdata=dnslib.A(ip), ttl=ttl))
            sock.sendto(answer.pack(), client)
            debug_(msg)
            debug_("\n%s\n" % answer)
            return

        if r_get:
            debug_(msg)
            debug_(r_get)
            r_get = dnslib.DNSRecord.pack(r_get)
            ret = dnslib.DNSRecord.parse(r_get)
            ret.header.id = qid
            sock.sendto(ret.pack(), client)
            return r_get

        elif whitelist_q(q_domain):
            dns_server = domesticserver
            dns_port = domesticport

        elif forward_q(q_domain):
            dns_server = foreignserver
            dns_port = foreignport

        elif gfw_q(q_name):
            dns_server = foreignserver
            dns_port = foreignport

        else:
            dns_server = domesticserver
            dns_port = domesticport

        reply = get_resolve(data, dns_server, dns_port)
        debug_(msg)
        if reply:
            for i in range(len(reply.rr)):
                reply.rr[i].ttl = ttl
            sock.sendto(reply.pack(), client)
            if forward_q(q_domain) or gfw_q(q_name):
                r_handler.r_set(redis_key, reply, redis_expire)

            debug_(reply)
        return reply

def get_resolve(data, dns_server, dns_port):
    i = 0
    while i < 5:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(data, (dns_server, dns_port))
            data, server = s.recvfrom(8192)
            reply = dnslib.DNSRecord.parse(data)
        except:
            i += 1
            continue
        else:
            return reply
    return

def _init_cache_queue():
    counter = 0
    while True:
        data, addr, sock = PORXY_DNS.deq_cache.get()
        try:
            gevent.spawn(handler, data, addr, sock)
        except:
            sys.exit(255)
        counter += 1
        time_ = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if debug:
            print "######################  %s ###################### %s ######################" % (counter, time_)

class DNSHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        if not PORXY_DNS.deq_cache.full():
            PORXY_DNS.deq_cache.put((self.request[0], self.client_address, self.request[1]))

class PORXY_DNS(object):
    @staticmethod
    def start():
        PORXY_DNS.deq_cache = Queue(maxsize=deq_size) if deq_size > 0 else Queue()
        PORXY_DNS.dns_cache = pylru.lrucache(lru_size)
        gevent.spawn(_init_cache_queue)
        print 'Start DNS server at %s:%d\n' % (server_ip, server_port)
        dns_server = SocketServer.UDPServer((server_ip, server_port), DNSHandler)
        dns_server.serve_forever()

def load_config(filename):
    with open(filename, 'r') as f:
        cfg = ConfigParser.ConfigParser()
        cfg.readfp(f)
    return dict(cfg.items('DEFAULT'))

def load_gfwlist(filename):
    with open(filename, 'r') as f:
        gfwlist = f.read()
    GFW_str = base64.b64decode(gfwlist)
    GFW_list_ = GFW_str.split('\n')
    start_list = GFW_list_.index("!---------------------Groups--------------------")
    end_list = GFW_list_.index("!################Whitelist Start################")
    GFW_list = GFW_list_[int(start_list):int(end_list)]
    return "".join(GFW_list)

def load_whitelist(filename):
    with open(filename,'r') as f:
        whitelist = f.read()
    whitelist = whitelist.split('\n')
    return "".join(whitelist)

def loadTxt(filename):
    result = {}
    with open(filename,'r') as f:
        for line in f:
            result[line.strip("\n").split("|")[0]] = line.strip("\n").split("|")[1]
    return result

if __name__ == '__main__':
    config_file = os.path.basename(__file__).split('.')[0] + '.conf'
    config_dict = load_config(config_file)
    server_ip, server_port = config_dict['server_ip'], int(config_dict['server_port'])
    redis_ip, redis_port = config_dict['redis_ip'], int(config_dict['redis_port'])
    redis_expire = int(config_dict['redis_expire'])
    domesticserver, domesticport = config_dict['domesticserver'], int(config_dict['domesticport'])
    foreignserver, foreignport = config_dict['foreignserver'], int(config_dict['foreignport'])
    deq_size, lru_size = int(config_dict['deq_size']), int(config_dict['lru_size'])
    ttl = int(config_dict['ttl'])
    gfwlist = load_gfwlist(config_dict['gfwlist'])
    forwardlist = load_whitelist(config_dict['forwardlist'])
    whitelist = load_whitelist(config_dict['whitelist'])
    cnamelist = loadTxt(config_dict['cname'])
    aList = loadTxt(config_dict['atxt'])
    debug = config_dict['debug']
    passwd = config_dict['redis_passwd']
    PORXY_DNS.start()
