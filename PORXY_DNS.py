#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/3/15 17:49
# @Author  : qiusong_chen@foxmail.com
# @Site    : 
# @File    : DNSserver.py.py
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
    def __init__(self, host, port, name):
        self.r = redis.Redis(host=host, port=int(port), decode_responses=True)
        self.name = name

    def r_get(self):
        tmp = self.r.get(self.name)
        if tmp:
            return pickle.loads(tmp)
        else:
            return None
    def r_set(self, key, value, redis_expire):
        self.r.set(key, pickle.dumps(value))
        self.r.expire(key, redis_expire)

def handler(data, client, sock):
    try:
        request = dnslib.DNSRecord.parse(data)

        qname = request.q.qname
        q_name_list = str(qname).split('.')
        q_name = ".".join(q_name_list[-3:len(q_name_list)-1])
        qid = request.header.id
        qtype = request.q.qtype
        qt = dnslib.QTYPE[qtype]
        redis_key = "%s_%s" %(qt, qname)
        r_handler = RedisHandler(redis_ip, redis_port, redis_key)
        r_get = r_handler.r_get()
        msg = "############### request domain is %s  ###############" % q_name
        debug_(msg)


    #except:
    #    sys.exit(255)
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
		debug_(reply)
		return

        if r_get:
            debug_(r_get)
            r_get = dnslib.DNSRecord.pack(r_get)
            ret = dnslib.DNSRecord.parse(r_get)
            ret.header.id = qid
            sock.sendto(ret.pack(), client)
            return r_get
        elif whitelist_q(q_name):
            dns_server = domesticserver
            dns_port = domesticport
        elif forward_q(q_name):
            dns_server = foreignserver
            dns_port = foreignport
        elif gfw_q(q_name):
            dns_server = foreignserver
            dns_port = foreignport
        else:
            dns_server = domesticserver
            dns_port = domesticport
	reply = get_dns(data, dns_server, dns_port)
        for i in range(len(reply.rr)):
            reply.rr[i].ttl = ttl
        sock.sendto(reply.pack(), client)
        r_handler.r_set(redis_key, reply, redis_expire)
        msg = "###############  request domain is  %s  ###############" % q_name
        debug_(msg)
        debug_(reply)
        return reply

def get_dns(data, dns_server, dns_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(data, (dns_server, dns_port))
        data, server = s.recvfrom(8192)
        reply = dnslib.DNSRecord.parse(data)
	return reply

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
            print "########################################## %s #########################################" % counter
            print "########################################## %s #########################################" % time_


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

def load_forwardlist(filename):
    with open(filename, 'r') as f:
            forwardlist = f.read()
    forwardlist = forwardlist.split('\n')
    return "".join(forwardlist)

def load_whitelist(filename):
    with open(filename,'r') as f:
            whitelist = f.read()
    whitelist = whitelist.split('\n')
    return "".join(whitelist)

def load_cname(filename):
    cname = {}
    with open(filename,'r') as f:
	for line in f:
		cname[line.strip("\n").split("|")[0]] = line.strip("\n").split("|")[1]
    return cname

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
    gfwlist_ = config_dict['gfwlist']
    gfwlist = load_gfwlist(config_dict['gfwlist'])
    forwardlist = load_forwardlist(config_dict['forwardlist'])
    whitelist = load_whitelist(config_dict['whitelist'])
    cnamelist = load_cname(config_dict['cname'])

    debug = config_dict['debug']
    PORXY_DNS.start()
