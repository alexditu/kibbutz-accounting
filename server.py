import socket
import Queue
import threading
from time import strftime, gmtime
from collections import namedtuple
from struct import unpack

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

IOU = namedtuple('IOU', 'k_pub, amount, h, seq')
IOU_FORMAT = ">I I I I"

iou_queue = Queue.Queue(-1)  # infinite size queue


def udp_server():
    """ UDP Server thread main function """

    sock = create_udp_server(UDP_IP, UDP_PORT)
    print "UDP server started"

    while True:
        data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
        print "[{}] size: {}, adr: {}, msg: {}".format(crt_time(), len(data), addr, data)

        add_iou(data)

        print iou_queue


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
    print "recv iou: {}".format(IOU._make(iou))

    iou_queue.put(IOU._make(iou))


def crt_time():
    fmt = "%a, %d %b %Y %H:%M:%S"
    return strftime(fmt, gmtime())


def process_iou_from_queue():
    iou = iou_queue.get()
    print "done processing iou: {}".format(iou)


def main():
    udp_server = start_server()

    while True:
        process_iou_from_queue()
        print ""


if __name__ == "__main__":
    main()