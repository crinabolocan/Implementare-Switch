#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)
    

def is_unicast(mac):
    first_byte = int(mac.split(':')[0], 16)
    return (first_byte & 1) == 0

def read_vlan_config(switch_id):
    vlan_config_switch = {}

    config_file_path = f'configs/switch{switch_id}.cfg'

    try:
        with open(config_file_path, 'r') as file:
            priority_switch = int(file.readline())

            for line in file:
                parts = line.strip().split(' ')
                interface_name = parts[0]
                interface_type = parts[1]
                if interface_type == 'T':
                    vlan_config_switch[interface_name] = {'type': 'T'}
                else:
                    vlan_config_switch[interface_name] = {'type': 'VLAN', 'vlan_id': parts[1]}
    except IOError:
        print(f'Could not open file {config_file_path}')
        exit(1)

    return vlan_config_switch


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    mac_table = {}
    vlan_config_switch = read_vlan_config(switch_id)
    print(f'VLAN config: {vlan_config_switch}')


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {hex(ethertype)}')
        print(f'data: {data}', flush=True)

        # TODO: Implement forwarding with learning
        if src_mac not in mac_table and src_mac != 'ff:ff:ff:ff:ff:ff':
            mac_table[src_mac] = interface

        if get_interface_name(interface) in vlan_config_switch:
            interface_type = vlan_config_switch[get_interface_name(interface)]['type']
        
                    
        if dest_mac != 'ff:ff:ff:ff:ff:ff':
            if dest_mac in mac_table:
                if vlan_config_switch[get_interface_name(mac_table[dest_mac])]['type'] == 'T':
                    if interface_type == 'T':
                        send_to_link(mac_table[dest_mac], data, length)
                    else:
                        data1 = data[0:12] + create_vlan_tag(int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])) + data[12:]
                        length1 = length + 4
                        send_to_link(mac_table[dest_mac], data1, length1)
                else:
                    if interface_type == 'T':
                        if (int(vlan_config_switch[get_interface_name(mac_table[dest_mac])]['vlan_id'])) == vlan_id:
                            data1 = data[0:12] + data[16:]
                            length1 = length - 4
                            send_to_link(mac_table[dest_mac], data1, length1)
                    else:
                        if (int(vlan_config_switch[get_interface_name(mac_table[dest_mac])]['vlan_id'])) == (int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])):
                            send_to_link(mac_table[dest_mac], data, length)


                # adresa de destinatie este in tabela de comutare, deci trimitem pe interfata respectiva
                # dest_interface = mac_table[dest_mac]
            else:
                # adresa de destinatie nu este in tabela de comutare, deci trimitem pe toate interfetele
                for i in interfaces:
                    if i != interface:
                        if vlan_config_switch[get_interface_name(i)]['type'] == 'T':
                            if interface_type == 'T':
                                send_to_link(i, data, length)
                            else:
                                data1 = data[0:12] + create_vlan_tag(int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])) + data[12:]
                                length1 = length + 4
                                send_to_link(i, data1, length1)
                        else:
                            if interface_type == 'T':
                                if (int(vlan_config_switch[get_interface_name(i)]['vlan_id'])) == vlan_id:
                                    data1 = data[0:12] + data[16:]
                                    length1 = length - 4
                                    send_to_link(i, data1, length1)
                            else:
                                if (int(vlan_config_switch[get_interface_name(i)]['vlan_id'])) == (int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])):
                                    send_to_link(i, data, length)
        else:
            # adresa de destinatie este broadcast, deci trimitem pe toate interfetele
            for i in interfaces:
                    if i != interface:
                        if vlan_config_switch[get_interface_name(i)]['type'] == 'T':
                            if interface_type == 'T':
                                send_to_link(i, data, length)
                            else:
                                data1 = data[0:12] + create_vlan_tag(int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])) + data[12:]
                                length1 = length + 4
                                send_to_link(i, data1, length1)
                        else:
                            if interface_type == 'T':
                                if (int(vlan_config_switch[get_interface_name(i)]['vlan_id'])) == vlan_id:
                                    # data = data[0:12] + data[16:]
                                    length1 = length - 4
                                    send_to_link(i, data[0:12] + data[16:], length1)
                            else:
                                if (int(vlan_config_switch[get_interface_name(i)]['vlan_id'])) == (int(vlan_config_switch[get_interface_name(interface)]['vlan_id'])):
                                    send_to_link(i, data, length)


        # TODO: Implement VLAN support
       




        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
