#!/usr/bin/env python3
"""PyBluez advanced example inquiry-with-rssi.py
Perform a simple device inquiry, followed by a remote name request of each
discovered device
"""

import struct
import sys
from socket import (
    socket,
    AF_BLUETOOTH,
    SOCK_RAW,
    BTPROTO_HCI,
    SOL_HCI,
    HCI_FILTER,
)
import subprocess
import bluetooth
import bluetooth._bluetooth as bluez  # low level bluetooth wrappers

get_byte = int

open_sock = None

def event_to_string(event):
    if event == bluez.EVT_INQUIRY_COMPLETE:
        return "EVT_INQUIRY_COMPLETE"

    if event == bluez.EVT_INQUIRY_RESULT:
        return "EVT_INQUIRY_RESULT"

    if event == bluez.EVT_CONN_COMPLETE:
        return "EVT_CONN_COMPLETE"

    if event == bluez.EVT_CONN_COMPLETE_SIZE:
        return "EVT_CONN_COMPLETE_SIZE"

    if event == bluez.EVT_CONN_REQUEST:
        return "EVT_CONN_REQUEST"

    if event == bluez.EVT_CONN_REQUEST_SIZE:
        return "EVT_CONN_REQUEST_SIZE"

    if event == bluez.EVT_DISCONN_COMPLETE:
        return "EVT_DISCONN_COMPLETE"

    if event == bluez.EVT_DISCONN_COMPLETE_SIZE:
        return "EVT_DISCONN_COMPLETE_SIZE"

    if event == bluez.EVT_AUTH_COMPLETE:
        return "EVT_AUTH_COMPLETE"

    if event == bluez.EVT_AUTH_COMPLETE_SIZE:
        return "EVT_AUTH_COMPLETE_SIZE"

    if event == bluez.EVT_REMOTE_NAME_REQ_COMPLETE:
        return "EVT_REMOTE_NAME_REQ_COMPLETE"

    if event == bluez.EVT_REMOTE_NAME_REQ_COMPLETE_SIZE:
        return "EVT_REMOTE_NAME_REQ_COMPLETE_SIZE"

    if event == bluez.EVT_ENCRYPT_CHANGE:
        return "EVT_ENCRYPT_CHANGE"

    if event == bluez.EVT_ENCRYPT_CHANGE_SIZE:
        return "EVT_ENCRYPT_CHANGE_SIZE"

    if event == bluez.EVT_READ_REMOTE_FEATURES_COMPLETE:
        return "EVT_READ_REMOTE_FEATURES_COMPLETE"

    if event == bluez.EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE:
        return "EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE"

    if event == bluez.EVT_READ_REMOTE_VERSION_COMPLETE:
        return "EVT_READ_REMOTE_VERSION_COMPLETE"

    if event == bluez.EVT_READ_REMOTE_VERSION_COMPLETE_SIZE:
        return "EVT_READ_REMOTE_VERSION_COMPLETE_SIZE"

    if event == bluez.EVT_QOS_SETUP_COMPLETE:
        return "EVT_QOS_SETUP_COMPLETE"

    if event == bluez.EVT_QOS_SETUP_COMPLETE_SIZE:
        return "EVT_QOS_SETUP_COMPLETE_SIZE"

    if event == bluez.EVT_CMD_COMPLETE:
        return "EVT_CMD_COMPLETE"

    if event == bluez.EVT_CMD_COMPLETE_SIZE:
        return "EVT_CMD_COMPLETE_SIZE"

    if event == bluez.EVT_CMD_STATUS:
        return "EVT_CMD_STATUS"

    if event == bluez.EVT_CMD_STATUS_SIZE:
        return "EVT_CMD_STATUS_SIZE"

    if event == bluez.EVT_ROLE_CHANGE:
        return "EVT_ROLE_CHANGE"

    if event == bluez.EVT_ROLE_CHANGE_SIZE:
        return "EVT_ROLE_CHANGE_SIZE"

    if event == bluez.EVT_NUM_COMP_PKTS:
        return "EVT_NUM_COMP_PKTS"

    if event == bluez.EVT_NUM_COMP_PKTS_SIZE:
        return "EVT_NUM_COMP_PKTS_SIZE"

    if event == bluez.EVT_MODE_CHANGE:
        return "EVT_MODE_CHANGE"

    if event == bluez.EVT_MODE_CHANGE_SIZE:
        return "EVT_MODE_CHANGE_SIZE"

    if event == bluez.EVT_PIN_CODE_REQ:
        return "EVT_PIN_CODE_REQ"

    if event == bluez.EVT_PIN_CODE_REQ_SIZE:
        return "EVT_PIN_CODE_REQ_SIZE"

    if event == bluez.EVT_LINK_KEY_REQ:
        return "EVT_LINK_KEY_REQ"

    if event == bluez.EVT_LINK_KEY_REQ_SIZE:
        return "EVT_LINK_KEY_REQ_SIZE"

    if event == bluez.EVT_LINK_KEY_NOTIFY:
        return "EVT_LINK_KEY_NOTIFY"

    if event == bluez.EVT_LINK_KEY_NOTIFY_SIZE:
        return "EVT_LINK_KEY_NOTIFY_SIZE"

    if event == bluez.EVT_MAX_SLOTS_CHANGE:
        return "EVT_MAX_SLOTS_CHANGE"

    if event == bluez.EVT_READ_CLOCK_OFFSET_COMPLETE:
        return "EVT_READ_CLOCK_OFFSET_COMPLETE"

    if event == bluez.EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE:
        return "EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE"

    if event == bluez.EVT_CONN_PTYPE_CHANGED:
        return "EVT_CONN_PTYPE_CHANGED"

    if event == bluez.EVT_CONN_PTYPE_CHANGED_SIZE:
        return "EVT_CONN_PTYPE_CHANGED_SIZE"

    if event == bluez.EVT_QOS_VIOLATION:
        return "EVT_QOS_VIOLATION"

    if event == bluez.EVT_QOS_VIOLATION_SIZE:
        return "EVT_QOS_VIOLATION_SIZE"

    if event == bluez.EVT_PSCAN_REP_MODE_CHANGE:
        return "EVT_PSCAN_REP_MODE_CHANGE"

    if event == bluez.EVT_FLOW_SPEC_COMPLETE:
        return "EVT_FLOW_SPEC_COMPLETE"

    if event == bluez.EVT_FLOW_SPEC_MODIFY_COMPLETE:
        return "EVT_FLOW_SPEC_MODIFY_COMPLETE"

    if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
        return "EVT_INQUIRY_RESULT_WITH_RSSI"

    if event == bluez.EVT_READ_REMOTE_EXT_FEATURES_COMPLETE:
        return "EVT_READ_REMOTE_EXT_FEATURES_COMPLETE"

    if event == bluez.EVT_EXTENDED_INQUIRY_RESULT:
        return "EVT_EXTENDED_INQUIRY_RESULT"

    if event == bluez.EVT_DISCONNECT_LOGICAL_LINK_COMPLETE:
        return "EVT_DISCONNECT_LOGICAL_LINK_COMPLETE"

    if event == bluez.EVT_IO_CAPABILITY_REQUEST:
        return "EVT_IO_CAPABILITY_REQUEST"

    if event == bluez.EVT_IO_CAPABILITY_RESPONSE:
        return "EVT_IO_CAPABILITY_RESPONSE"

    if event == bluez.EVT_USER_CONFIRM_REQUEST:
        return "EVT_USER_CONFIRM_REQUEST"

    if event == bluez.EVT_SIMPLE_PAIRING_COMPLETE:
        return "EVT_SIMPLE_PAIRING_COMPLETE"

    if event == bluez.EVT_TESTING:
        return "EVT_TESTING"

    if event == bluez.EVT_VENDOR:
        return "EVT_VENDOR"

    if event == bluez.EVT_STACK_INTERNAL:
        return "EVT_STACK_INTERNAL"

    if event == bluez.EVT_STACK_INTERNAL_SIZE:
        return "EVT_STACK_INTERNAL_SIZE"

    if event == bluez.EVT_SI_DEVICE:
        return "EVT_SI_DEVICE"

    if event == bluez.EVT_SI_DEVICE_SIZE:
        return "EVT_SI_DEVICE_SIZE"

    if event == bluez.EVT_NUMBER_COMPLETED_BLOCKS:
        return "EVT_NUMBER_COMPLETED_BLOCKS"

    return "Unknown event"


def printpacket(pkt):
    print(pkt.hex())

def hexlist(bytes_list):
    return '[{}]'.format(', '.join(hex(x) for x in bytes_list))

def send_create_connection(hci_sock, peer_address):
    address = bytearray(peer_address)
    packet_type = struct.pack("H", 0xcc18)
    page_scan_mode = struct.pack("B", 0x01)
    page_scan_mandatory_mode = struct.pack("B", 0x00)
    clock_offset = struct.pack("H", 0x0000)
    allow_role_switch = struct.pack("B", 0x01)
    data = address + packet_type + page_scan_mode + page_scan_mandatory_mode + clock_offset + allow_role_switch
    data = bytes(data)
    bluez.hci_send_cmd(hci_sock, bluez.OGF_LINK_CTL, bluez.OCF_CREATE_CONN, data)

def read_local_bdaddr(use_exclusive):
    hci_sock = None
    if use_exclusive:
        a = bluetooth.BluetoothSocket(proto=bluetooth.HCI)
        hci_sock = a._sock
        res = hci_sock.bind((0, bluez.HCI_CHANNEL_USER))
        open_sock = hci_sock
    else:
        hci_sock = bluez.hci_open_dev(0)
        old_filter = hci_sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_all_ptypes(flt)
        hci_sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    #send_create_connection(hci_sock, [0xad, 0x7e, 0x59, 0x36, 0x4e, 0x40])
    send_create_connection(hci_sock, [0xf0, 0x86, 0xab, 0x0a, 0x66, 0xcc])

    while True:
        pkt = hci_sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        print("Event: {}".format(event))
        print("event name: " + event_to_string(event))
        if ptype == bluez.HCI_EVENT_PKT and event == bluez.EVT_CMD_COMPLETE:
            num_complete, ocf, status = struct.unpack("BHB", pkt[3:3+5])
            print("ocf:" + str(ocf))
            #break
        elif ptype == bluez.HCI_EVENT_PKT and event == bluez.EVT_CMD_STATUS:
            status, num_complete, opcode = struct.unpack("BBH", pkt[3:3+4])
            print("opcode:" + hex(opcode) + " status:" + hex(status))
            #break
        elif ptype == bluez.HCI_EVENT_PKT and event == bluez.EVT_CONN_COMPLETE:
            output = struct.unpack("<BH6BBB", pkt[3:3+11])
            status = output[0]
            conn_handle = output[1]
            bd_addr = output[2:8]
            link_type = output[9:10]
            encryption_enabled = output[10:11]
            print(output)
            print(conn_handle)
            print("address:" + hexlist(bd_addr) + " status:" + hex(status))
            #break
        else:
            print("Unrecognized packet 0x{:02x} : 0x{:02x}".format(ptype, event))

    # restore old filter
    if use_exclusive:
        hci_sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )

# allow us to take over control
process = subprocess.Popen(['sudo', 'hciconfig', 'hci0', 'down'],
                     stdout=subprocess.PIPE, 
                     stderr=subprocess.PIPE)
stdout, stderr = process.communicate()
print(stdout)

# try:
#     read_local_bdaddr(True)
# except KeyboardInterrupt:
#     if open_sock is not None:
#         open_sock.close()

read_local_bdaddr(True)



# a = bluetooth.BluetoothSocket(proto=bluetooth.HCI)
# print(a._sock)
# my_socket = a._sock
# res = my_socket.bind((0, bluez.HCI_CHANNEL_USER))
# #my_socket = a.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
# send_create_connection(my_socket, [0xf0, 0x86, 0xab, 0x0a, 0x66, 0xcc])
# while True:
#     pkt = my_socket.recv(255)
#     print(pkt)
    
# s = bluez.btsocket()
# print(s)
# ret = s.bind(("0", bluez.HCI_CHANNEL_USER))
# s.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

# https://www.py4u.net/discuss/184937
# https://www.spinics.net/lists/linux-bluetooth/msg37345.html
