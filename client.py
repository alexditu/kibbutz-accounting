#!/usr/bin/python

import socket
import time
import sys
from collections import namedtuple
from subprocess import Popen, PIPE
from struct import pack, unpack

UDP_IP = "10.0.3.1"
UDP_PORT = 5005
SERVER_ADDR = (UDP_IP, UDP_PORT)

IPTables_data = namedtuple('IPTables_data', 'num pkts bytes target prot opt in_ out source destination comment')
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

IOU = namedtuple('IOU', 'k_pub, amount, h, seq, exp, sign')
IOU = namedtuple('IOU', 'k_pub, amount, h, seq')
IOU_FORMAT = ">I I I I"  # k_pub, amount, h, seq = 4 x 4 bytes = 16 bytes

total_recv = 0
total_accounted = 0
seq = -1
iou_history = []


# TODO: method not tested!!
def apply_iptables_rules(server_ip):
    INBOUND_RULE_TEMPLATE = '-t filter -A INPUT -j NFLOG --nflog-prefix  "INBOUND "'
    OUTBOUND_RULE_TEMPLATE = '-t filter -A OUTPUT -j NFLOG --nflog-prefix  "OUTBOUND " ! -d {}/32'

    inbound_rule = INBOUND_RULE_TEMPLATE
    outbound_rule = OUTBOUND_RULE_TEMPLATE.format(server_ip)

    Popen("iptables " + inbound_rule, shell=True)
    Popen("iptables " + outbound_rule, shell=True)


def parse_iptables_input(line):
    line = remove_white_spaces(line)
    return IPTables_data._make(line)


def remove_white_spaces(line):
    return (" ".join(line.split())).split(' ', 10)


def send_iou(iou):
    bytes_sent = sock.sendto(iou, SERVER_ADDR)
    print "sent [{}] bytes".format(bytes_sent)
    if bytes_sent == 0:
        print "Message sent failed for iou: {}".format(iou)


def zero_iptables_buffers():
    Popen("iptables -t filter -Z INPUT", shell=True)
    Popen("iptables -t filter -Z OUTPUT", shell=True)


def read_iptables_data(ip = "0.0.0.0"):
    cmd = "iptables -t filter -L INPUT --line-numbers -nvx | grep {}"
    cmd = cmd.format(ip)

    line = Popen(cmd, shell=True, stdout=PIPE).stdout.readline()
    print "line: {}".format(line)

    data = parse_iptables_input(line)
    return data


def generate_iou():
    global total_accounted
    global total_recv
    global seq

    data = read_iptables_data()

    crt_bytes = int(data.bytes)
    crt_accounting = crt_bytes - total_recv
    total_recv = crt_bytes
    seq += 1

    # k_pub, amount, h, seq
    iou = [256, crt_accounting, crt_bytes, seq]
    print "IOU: {}".format(iou)

    packed_iou = pack(IOU_FORMAT, *iou)
    print packed_iou.encode("hex")

    return iou


def print_globals():
    global total_accounted
    global total_recv
    global seq

    print "globals: {}, {}, {}".format(total_recv, total_accounted, seq)


def main():
    # print 'total args: {}: {}'.format(len(sys.argv), sys.argv)

    while True:
        iou = generate_iou()
        packed_iou = pack(IOU_FORMAT, *iou)
        send_iou(packed_iou)
        time.sleep(4)

if __name__ == "__main__":
    main()














