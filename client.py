#!/usr/bin/python

import socket
import time
import sys
from collections import namedtuple
from subprocess import Popen, PIPE

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
SERVER_ADDR = (UDP_IP, UDP_PORT)

IPTables_data = namedtuple('IPTables_data', 'num pkts bytes target prot opt in_ out source destination comment')
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

IOU = namedtuple('IOU', 'k_pub, amount, h, seq, exp, sign')
IOU = namedtuple('IOU', 'k_pub, amount, h, seq')
IOU_FORMAT = "<4sLLL"  # k_pub, amount, h, seq

total_recv = 0
total_accounted = 0
seq = 0
iou_history = []


def parse_iptables_input(line):
    line = remove_white_spaces(line)
    return IPTables_data._make(line)


def remove_white_spaces(line):
    return (" ".join(line.split())).split(' ', 10)


def send_iou(iou):
    bytes_sent = sock.sendto(iou, SERVER_ADDR)
    if bytes_sent == 0:
        print "Message sent failed for iou: {}".format(iou)


def read_iptables_data(ip = "0.0.0.0"):
     cmd = "iptables -t filter -L INPUT --line-numbers -nvx | grep {}"
     cmd = cmd.format(ip)

     line = Popen(cmd, shell=True, stdout=PIPE).stdout.readline()
     print "line: {}".format(line)


def generate_iou():
    iou = None

    return iou

def main():
    print 'total args: {}'.format(len(sys.argv))

    read_iptables_data()
    # while True:
    #     iou = generate_iou()
    #     send_iou(iou)
    #     time.sleep(2)

if __name__ == "__main__":
    main()














