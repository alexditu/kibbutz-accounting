import socket
import Queue
import threading
from time import sleep
from time import strftime, gmtime
from collections import namedtuple
from struct import unpack
from subprocess import Popen, PIPE

UDP_IP = "10.0.3.1"
UDP_PORT = 5005

IOU = namedtuple('IOU', 'k_pub, amount, h, seq')
IOU_FORMAT = ">I I I I"

IPTables_data = namedtuple('IPTables_data', 'num pkts bytes target prot opt in_ out source destination comment')

iou_queue = Queue.LifoQueue(-1)  # infinite size queue


def udp_server():
    """ UDP Server thread main function """

    sock = create_udp_server(UDP_IP, UDP_PORT)
    print "UDP server started"

    while True:
        data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        # print "[{}] size: {}, adr: {}, msg: {}".format(crt_time(), len(data), addr, data)

        add_iou(data)


def create_udp_server(udp_ip, udp_port):
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    sock.bind((udp_ip, udp_port))
    return sock


def start_server():
    t = threading.Thread(target=udp_server)
    t.start()
    return t


def add_iou(packed_iou):
    if len(packed_iou) != 16:
        raise Exception("invalid iou size: {}, must be 16".format(len(packed_iou)))

    iou = unpack(IOU_FORMAT, packed_iou)
    # print "recv iou: {}".format(IOU._make(iou))

    iou_queue.put(IOU._make(iou))


def crt_time():
    fmt = "%a, %d %b %Y %H:%M:%S"
    return strftime(fmt, gmtime())


# TODO: method not tested!!
def apply_iptables_rules(client_ip, client_alias):
    INBOUND_RULE_TEMPLATE = '-t filter -A FORWARD -d {}/32 -j LOG --log-prefix "{}__INBOUND "'
    OUTBOUND_RULE_TEMPLATE = '-t filter -A FORWARD -s {}/32 -j LOG --log-prefix "{}_OUTBOUND "'

    inbound_rule = INBOUND_RULE_TEMPLATE.format(client_ip, client_alias)
    outbound_rule = OUTBOUND_RULE_TEMPLATE.format(client_ip, client_alias)

    Popen("iptables " + inbound_rule, shell=True)
    Popen("iptables " + outbound_rule, shell=True)


def parse_iptables_output(line):
    line = remove_white_spaces(line)
    return IPTables_data._make(line)


def remove_white_spaces(line):
    return (" ".join(line.split())).split(' ', 10)


def zero_iptables_buffers():
    Popen("iptables -Z FORWARD", shell=True)


def read_iptables_data(ip, client_alias):
    IPTABLES_CMD = "iptables -nvxL FORWARD --line-numbers | grep {} | grep {}"
    cmd = IPTABLES_CMD.format(ip, client_alias)

    iptables_output = Popen(cmd, shell=True, stdout=PIPE).stdout
    for line in iptables_output:
        if "INBOUND" in line:
            inbound = parse_iptables_output(line)
        elif "OUTBOUND" in line:
            outbound = parse_iptables_output(line)
        else:
            raise Exception("iptables output line invalid format: {}".format(line))

    # print "inbound data: {}".format(inbound)

    return [inbound, outbound]


in_bytes_last = 0
in_bytes = 0
in_bytes_acc = 0
in_seq = -1


# TODO: much work to be done here..
def update_counters(ip, client_alias):
    global in_bytes
    global in_bytes_acc
    global in_seq

    data = read_iptables_data(ip, client_alias)
    inbound = data[0]
    # print "inbound: {}".format(inbound)
    in_bytes = int(inbound.bytes)


def validate_iou(iou, db):
    global in_bytes
    global in_bytes_acc
    global in_bytes_last
    global in_seq

    if in_seq > iou.seq:
        print "discard: {}, in_seq: {}".format(iou, in_seq)
        return

    print "iou: {}".format(iou)
    print "in_bytes_last: {}, in_bytes: {}, in_bytes_acc: {}".format(in_bytes_last, in_bytes, in_bytes_acc)

    if in_bytes > iou.amount:
        print "\tERROR: server = {}, client = {}".format(in_bytes, iou.amount)

    amount = in_bytes - in_bytes_last
    in_bytes_acc += amount
    in_bytes_last = in_bytes
    in_seq = iou.seq

    iou_str = "[amount: {}, seq: {}, total: {}]".format(amount, iou.seq, in_bytes_acc)
    print iou_str

    if amount != 0:
        db.write(iou_str + "\n")



def process_iou_from_queue(db):
    iou = iou_queue.get()
    validate_iou(iou, db)


def main():
    ip = "10.0.3.11"
    alias = "CT1"
    udp_server_thread = start_server()

    print "started counting"

    try:
        db = open("server.db", "w")
        while True:
            update_counters(ip, alias)
            process_iou_from_queue(db)
            sleep(2)
            print ""
    finally:
        db.close()


if __name__ == "__main__":
    main()
