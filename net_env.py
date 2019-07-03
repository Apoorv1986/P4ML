import numpy as np
from scapy.all import *
from scapy.all import Ether, ICMP, IP, TCP, UDP, Raw
import binascii
import paramiko
import json

Host_IP = '192.168.102.224'
#Host_IP = '192.168.178.36'
header_array = []

offset_list=[14,15,16,18,20,22,23,24,26,30]
packet_header_list=[]
ip_address_list=[]
other_ip_fields_list=[]
ip_to_port = {}
port_to_mac = {}

vers_len_ip_list=[]
tos_id_ip_list=[]
len_id_ip_list=[]
id_flags_ip_list=[]
flags_proto_ip_list=[]
ttl_chksum_ip_list=[]

valid_dst_ips = []
invalid_dst_ips = []
valid_macs = []

################################## Class for network environment #######################################################
    # Creates the environment the agent will interact with
    # States are defined as a "substring" of a packet header
    # Actions are pre-defined in action_set
    # As start state a header out of header_array is randomly chosen and a random sample with size width is chosen as
    # "substring" describing the initial state
    # Input:
    #   width: number of bytes (size of the states)
    # Returns:
    #   environment for agents to use
class networkEnv():
    def __init__(self, width, verbose):
        self.actions = 2
        self.x = bytearray()
        self.width = width
        self.offset = 0
        self.debug = verbose
        self.right_boundary = 1
        self.state = bytes()
        self.header_field = bytes()
        self.offset_list = []
        self.valid_dst_ips_temp = []
        self.valid_macs_temp = []
        self.ip_to_port = {}
        self.port_to_dstmac = {}
        self.match_to_port = {}
        self.table_entries = {}
        self.receive_stop = False
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_server_tread = threading.Thread(target=self.socket_server).start()

        self.initialize_lists()
        self.reset()
        self.reward_system = rewardSys(verbose=verbose)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return

    def __del__(self):
        print("Network Env deleted")

    def clean_up(self):
        print("cleaning now")
        self.reward_system.cleanup()
        time.sleep(1)
        del self.reward_system

    def socket_server(self):
        if self.udp is None:
            print("udp is None")
        try:
            print("starting UDP server")
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp.bind((Host_IP, 9999))
        except:
            print("Nope the UDP socket could not be bound")

        input_ = [self.udp]
        verbose = self.debug
        def parse_json(msg):
            self.receive_stop = True
            self.udp=None
            json_msg = json.loads(msg, encoding = "ISO-8859-1")
            print("got to json parser")
            print(json_msg)
            self.table_entries = json_msg
            for entry in json_msg['table_entries']:
                if 'port' in entry['action_params']:
                    for key in entry['action_params'].keys():
                        if ('addr' in key) or ('Addr' in key):
                            print("key: ", key)
                            print('addr in key: ', ('addr' in key) or ('Addr' in key))
                            self.port_to_dstmac[int.from_bytes(entry['action_params']['port'].encode(), byteorder='big')] = entry['action_params'][key]
                            if entry['action_params'][key] != '00:00:00:00:01:01':
                                self.valid_macs_temp.append(entry['action_params'][key])
                    for val in entry['match'].keys():
                        if 'ip' in val:
                            self.ip_to_port[entry['match'][val]] = int.from_bytes(entry['action_params']['port'].encode(), byteorder='big')
                            if entry['match'][val]!= '10.0.1.1':
                                self.valid_dst_ips_temp.append(entry['match'][val])

        def receive_stop():
            self.receive_stop = True
        ######################## UDP and TCP corresponding clients ############################
        # UDP client to receive the messages
        # Parameters:
        #   Input:
        #   Output:
        class Client(Thread):
            def __init__(self, socket, address, sock_type):
                Thread.__init__(self)
                self.sock = socket
                self.addr = address
                self.type = sock_type
                self.start()

            def run(self):
                while 1:
                    if verbose:
                        print("Client sent:")
                    if self.type == "udp":
                        try:
                            msg, address = self.sock.recvfrom(1024)
                            print(address)
                        except OSError:
                            msg = None
                            print("OS Error: ", OSError)

                        if verbose:
                            print("message:", msg)
                        if msg is None:
                            break
                        else:
                            parse_json(msg)
                            receive_stop()
                        break
                    else:
                        break
        if self.debug:
            print("server started and is listening")

        nothing_recv=True
        while not self.receive_stop:
            if self.udp is None:
                print("udp is None")
                break

            # check for TCP or UDP connection and call the right client
            s = None
            try:
                inputready, outputready, exceptready = select(input_, [], [])
                for s in inputready:
                    if s == self.udp:
                        Client(s, None, "udp")

            except KeyboardInterrupt:
                if s:  # <---
                    s.close()
                break  # <---
            except ValueError:
                print("Value error: ", ValueError)
                if s:  # <---
                    s.close()
                if self.udp:
                    self.udp.close()
                break  # <---

        print("shutdown and close executed")
        try:
            self.udp.close()
        except:
            return

    def initialize_lists(self):
        time.sleep(10)
        if self.udp is not None:
            try:
                self.udp.shutdown(2)
            except OSError:
                print("OS Error: ", OSError)
                pass
            self.udp.close()
            time.sleep(1)
            self.udp = None

        valid_dst_ips.extend(self.valid_dst_ips_temp)
        rand_ip_list = []
        for i in range(1000):
            rand_ip = np.random.randint(low=0, high=256,size=4)
            rand_ip_list.append("{}.{}.{}.{}".format(rand_ip[0], rand_ip[1], rand_ip[2], rand_ip[3]))

        invalid_dst_ips.extend(rand_ip_list)
        valid_macs.extend(self.valid_macs_temp)
        ip_to_port.update(self.ip_to_port)
        port_to_mac.update(self.port_to_dstmac)
        print("self.table_entries: ", self.table_entries)
        print("self.ip_to_port: ", self.ip_to_port)
        print("self.port_to_mac: ", self.port_to_dstmac)
        print("valid_ips: ", valid_dst_ips)
        print("valid_macs: ", valid_macs)

        packet_header_list.clear()
        ip_address_list.clear()
        other_ip_fields_list.clear()
        vers_len_ip_list.clear()
        tos_id_ip_list.clear()
        len_id_ip_list.clear()
        id_flags_ip_list.clear()
        flags_proto_ip_list.clear()
        ttl_chksum_ip_list.clear()
        header_array.clear()
        header_array.append(bytes(Ether(src='00:00:00:00:00:02', dst='10:00:00:00:00:01') /
                                  IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=5000, dport=5111)))
        for i in range(0, 1000):

            pkt = Ether(src=valid_macs[np.random.randint(0, len(valid_macs))], dst=valid_macs[np.random.randint(0, len(valid_macs))]) / \
                      IP(version=np.random.choice([4, np.random.randint(0, 16)], p=[0.8, 0.2]),
                         ihl=np.random.choice([np.random.randint(4,6), np.random.randint(0, 15)], p=[0.8, 0.2]),
                         tos=np.random.randint(0, 256),
                         len=np.random.choice([np.random.randint(19, 21), np.random.choice(range(0,61,4)), np.random.randint(0, 65536)], p=[0.4,0.4, 0.2]),
                         id=np.random.randint(0, 65536),
                         flags=np.random.randint(0, 8),
                         frag=np.random.randint(0, 8192),
                         ttl=np.random.choice([np.random.randint(0,2), np.random.randint(0,256)], p=[0.9,0.1]),
                         proto=np.random.randint(0, 256),
                         src=valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                         dst=valid_dst_ips[np.random.randint(0, len(valid_dst_ips))]) / np.random.bytes(40)#TCP(sport=5678, dport=1234)/ TCP(sport=5678, dport=1234)

            pkt_2 = Ether(src=valid_macs[np.random.randint(0, len(valid_macs))], dst=valid_macs[np.random.randint(0, len(valid_macs))]) / \
                      IP(version=np.random.choice([4, np.random.randint(0, 16)], p=[0.95, 0.05]),
                         ihl=np.random.choice([5, np.random.randint(6, 15)], p=[0.95, 0.05]),
                         tos=np.random.randint(0, 256),
                         len=np.random.choice([np.random.randint(40, 80), np.random.randint(20, 65536)], p=[0.95, 0.05]),
                         id=np.random.randint(0, 65536),
                         flags=np.random.randint(0, 8),
                         frag=np.random.randint(0, 8192),
                         ttl=np.random.choice([np.random.randint(0, 2), np.random.randint(0, 256)], p=[0.001, 0.999]),
                         proto=np.random.randint(0, 256),
                         src=np.random.choice([valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                                               invalid_dst_ips[np.random.randint(0, len(invalid_dst_ips))]], p=[0.9,0.1]),
                         dst=np.random.choice([valid_dst_ips[np.random.randint(0, len(valid_dst_ips))],
                                               invalid_dst_ips[np.random.randint(0, len(invalid_dst_ips))]], p=[0.9,0.1])) / TCP(sport=5678, dport=1234)

            try:
                pkt = Ether(bytes(pkt))
                pkt = bytes(pkt)
                pkt_2 = Ether(bytes(pkt_2))
                pkt_2 = bytes(pkt_2)
                packet_header_list.append(pkt_2)
                ip_address_list.append(pkt[26:30])
                ip_address_list.append(pkt[30:34])
                other_ip_fields_list.append(pkt[14:18])
                other_ip_fields_list.append(pkt[15:19])
                other_ip_fields_list.append(pkt[16:20])
                other_ip_fields_list.append(pkt[18:22])
                other_ip_fields_list.append(pkt[20:24])
                other_ip_fields_list.append(pkt[22:26])

                vers_len_ip_list.append(pkt[14:18])
                tos_id_ip_list.append(pkt[15:19])
                len_id_ip_list.append(pkt[16:20])
                id_flags_ip_list.append(pkt[18:22])
                flags_proto_ip_list.append(pkt[20:24])
                ttl_chksum_ip_list.append(pkt[22:26])
            except:
                print("didnt work")
        print("vers_len_ip_list length: ", len(vers_len_ip_list))
        print("len_id_ip_list length: ", len(len_id_ip_list))
        print("flags_proto_ip_list length: ", len(flags_proto_ip_list))


################################## reset network environment ###########################################################
    # Resets the state of the environment by chosing random sample from header_array and randomly choose a "substring"
    # with size width
    # Input:
    #   -
    # Returns:
    #   resetted environment
    def reset(self):
        self.offset_list = []
        self.x = bytearray(bytes(packet_header_list[np.random.randint(0,len(packet_header_list))]))
        if self.debug:
            print("offset: ", self.offset)
            print("right_boundary: ", self.right_boundary)
            print("type offset: " , type(self.offset))
            print("type right_boundary: ", type(self.right_boundary))
        x_1 = self.x[14:34]
        state = x_1
        self.state = state
        if self.debug:
            print("length of state is: ", len(state))
        return state

################################## apply action chosen by agent ########################################################
    # Applies action chosen by agent in current step by calling execute() and evaluates its reward by calling
    # check_reward()
    # Input:
    #   action: action_set index defining the action to be executed
    # Returns:
    #   reward: reward of the agent after executing action
    def apply_action(self, action):
        result = self.execute(action)
        reward = self.check_reward()
        return reward

################################## retrieve agent's reward #############################################################
    # Creates packet with modified header and sends it to P4 program to be tested
    # Calculates reward for agent
    # Input:
    #   -
    # Returns:
    #   reward: reward of the agent after executing action
    def check_reward(self):
        x = self.x
        # recalculate checksum if fields are modified at an offset that does not include the IP checksum
        if (22 in self.offset_list) or (23 in self.offset_list) or (24 in self.offset_list):
            pkt = Ether(bytes(x))
        # if checksum field is specifically modified dont recalculate checksum to trigger sent_checksum bug
        else:
            pkt = Ether(bytes(x))
            del pkt[IP].chksum
            pkt = Ether(bytes(pkt))
        reward = self.reward_system.send_packet_and_generate_reward(pkt)
        return reward

    def check_random_reward(self):
        x = np.random.bytes(60)
        pkt = Ether(bytes(x))
        reward = self.reward_system.send_packet_and_generate_reward(pkt)

    def copy_bytes_from_ether_list(self):
        result = 0
        return result

    def copy_bytes_from_other_ip_fields_list(self):
        result = np.random.choice(other_ip_fields_list)
        return result

    def copy_bytes_from_vers_len_ip_list(self):
        result = np.random.choice(vers_len_ip_list)
        return result

    def copy_bytes_from_tos_id_ip_list(self):
        result = np.random.choice(tos_id_ip_list)
        return result

    def copy_bytes_from_len_id_ip_list(self):
        result = np.random.choice(len_id_ip_list)
        return result

    def copy_bytes_from_id_flags_ip_list(self):
        result = np.random.choice(id_flags_ip_list)
        return result

    def copy_bytes_from_flags_proto_ip_list(self):
        result = np.random.choice(flags_proto_ip_list)
        return result

    def copy_bytes_from_ttl_chksum_ip_list(self):
        result = np.random.choice(ttl_chksum_ip_list)
        return result

    def copy_bytes_from_ip_address_list(self):
        result = np.random.choice(ip_address_list)
        return result

################################## execute chosen action ###############################################################
    # Execute specified action to modify the given part of the header
    # Input:
    #   action: string retrieved from action_set defining the action to be executed
    # Returns:
    #   modified header part
    def execute(self, action):
        reward = None
        if action == 0:
            self.offset = 14
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 1:
            self.offset = 15
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 2:
            self.offset = 16
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 3:
            self.offset = 18
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 4:
            self.offset = 20
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 5:
            self.offset = 22
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 6:
            self.offset = 23
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 7:
            self.offset = 24
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 8:
            self.offset = 26
            self.right_boundary = self.offset + self.width
            self.header_field = np.random.bytes(self.width)
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 9:
            self.offset = 14
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_vers_len_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 10:
            self.offset = 15
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_tos_id_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 11:
            self.offset = 16
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_len_id_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 12:
            self.offset = 18
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_id_flags_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 13:
            self.offset = 20
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_flags_proto_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 14:
            self.offset = 22
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ttl_chksum_ip_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 15:
            self.offset = 26
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ip_address_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 16:
            self.offset = 30
            self.right_boundary = self.offset + self.width
            self.header_field = self.copy_bytes_from_ip_address_list()
            self.x[self.offset:self.right_boundary] = self.header_field
            self.offset_list.append(self.offset)
            self.state = self.x[14:34]
        elif action == 17:
            pass
        elif action == 18:
            reward = self.check_reward()
        elif action == 19:
            pass
        return self.state, reward

################################## Class for reward system #############################################################
    # Uses SSH client to connect to specified VirtualBox VM and sends a given packet using send.py script (scapy)
    # Receives Mininet Egress Packet and compares it using defined comparison rules to generate the Agent's reward
    #
    # Input:
    #   packet: packet to be sent to the Mininet network
    # Returns:
    #   reward: Int; indicating agent's reward
class rewardSys():

    def __init__(self, verbose):

        self.debug = verbose
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_server_tread = threading.Thread(target=self.socket_server).start()
        self.sshC = sshClient(verbose=verbose)
        self.sshC.connect()
        self.dropped = False
        self.bug = False
        # adjustable parameter for agent execution testing for different queries
        self.run = 0
        self.received_packet = None
        self.recv_port = None
        self.reward = None
        self.valid_ips = []
        self.valid_macs = []

    def __enter__(self):
        return self

    def __del__(self):
        print("reward sys deleted")

    def cleanup(self):
        print("came to cleanup")
        print("signal set to false")
        time.sleep(0.1)
        print("slept 0.1 secs")
        self.sshC.disconnect()
        del self.sshC
        try:
            self.udp.shutdown(2)
        except OSError:
            print("OS Error: ", OSError)
            pass
        self.udp.close()
        time.sleep(1)
        self.udp = None
        print("sshc disconnected")

    def send_packet_and_generate_reward(self, pkt):
        self.received_packet = None
        self.recv_port = None
        self.bug = False
        self.sshC.send_packet(pkt)
        reward = self.generate_reward()
        return reward

    def generate_reward(self):
        i=20
        while self.received_packet is None:
            time.sleep(0.1)
            if i>0:
                i-=1
            else:
                self.dropped=True
                break
        recv_packet = self.received_packet
        egr_port= self.recv_port
        reward = self.compare_packets(recv_packet, egr_port)
        if self.debug:
            print("Reward: ", reward)
        return reward

    def compare_packets(self, pkt, port):
        egr_port = port
        reward = 0
        self.received_packet = pkt
        if self.received_packet:
            self.received_packet = Ether(bytes(self.received_packet))
        sent_packet = self.sshC.sent_packet
        if self.debug:
            print("sent packet: ")
            sent_packet.show2()
        if self.debug:
            print("sent_ihl: ", self.sshC.sent_packet[IP].ihl)
        if pkt:
            self.dropped = False
        else:
            self.dropped = True
        if self.debug:
            print("self.dropped: ", self.dropped)
        # Parse received packet:
        recv_src_mac = 0
        recv_dst_mac = 0
        recv_ether_type = 0
        recv_src_ip = 0
        recv_dst_ip = 0
        recv_ttl = 0
        recv_ihl = 0
        recv_chksum = 0
        recv_proto = 0
        recv_tos = 0
        recv_version = 0
        recv_len = 0
        recv_id = 0
        if self.received_packet and Ether in self.received_packet:
            recv_src_mac = self.received_packet[Ether].src
            recv_dst_mac = self.received_packet[Ether].dst
            recv_ether_type = self.received_packet[Ether].type
        if self.received_packet and IP in self.received_packet:
            recv_src_ip = self.received_packet[IP].src
            recv_dst_ip = self.received_packet[IP].dst
            recv_ttl = self.received_packet[IP].ttl
            recv_ihl = self.received_packet[IP].ihl * 4
            recv_version = self.received_packet[IP].version
            recv_chksum = self.received_packet[IP].chksum
            recv_proto = self.received_packet[IP].proto
            recv_tos = self.received_packet[IP].tos
            recv_len = self.received_packet[IP].len
            recv_id = self.received_packet[IP].id

        # Parse sent packet:
        sent_src_mac = None
        sent_dst_mac = None
        sent_ether_type = None
        sent_src_ip = None
        sent_dst_ip = None
        sent_ttl = None
        sent_version = None
        sent_ihl = None
        sent_chksum = None
        sent_proto = None
        sent_tos = None
        sent_len = None
        sent_id = None

        if Ether in sent_packet:
            sent_src_mac = sent_packet[Ether].src
            sent_dst_mac = sent_packet[Ether].dst
            sent_ether_type = sent_packet[Ether].type
        if IP in sent_packet:
            if self.debug:
                print("went to sent_packet ip header")
            sent_src_ip = sent_packet[IP].src
            sent_dst_ip = sent_packet[IP].dst
            sent_ttl = sent_packet[IP].ttl
            sent_ihl = sent_packet[IP].ihl
            sent_version = sent_packet[IP].version
            sent_chksum = sent_packet[IP].chksum
            sent_proto = sent_packet[IP].proto
            sent_tos = sent_packet[IP].tos
            sent_len = sent_packet[IP].len
            sent_id = sent_packet[IP].id
        if self.debug:
            print("sent_ihl: ", sent_ihl)
            print("sent_src_ip: ", sent_src_ip)
            print("sent_version: ", sent_version)

        if self.received_packet:
            if self.debug:
                print("recv_version: ", self.received_packet[IP].version)
        # recalculate the checksum to see if its correct in case a packet is received
        if not self.dropped:
            if self.debug:
                print("recv_chksum: ", recv_chksum)
            del self.received_packet.chksum
            self.received_packet = Ether(bytes(self.received_packet))
            correct_recv_cksum = self.received_packet[IP].chksum
            if self.debug:
                print("correct checksum: ", correct_recv_cksum)
                print("self.dropped: ", self.dropped)
                print("comparison: ", recv_chksum!=correct_recv_cksum)
                print("compare with dropped: ", (recv_chksum!=correct_recv_cksum) and not self.dropped)
            actual_recv_len = len(self.received_packet)
        else:
            correct_recv_cksum = 0
            actual_recv_len = 0
        # recalculate the checksum to see if its correct
        if IP in sent_packet:
            del sent_packet[IP].chksum
            sent_packet = Ether(bytes(sent_packet))
        # Rule 1: Check if initial TTL was high enough to reach the Egress and if yes check if the decrement worked
            correct_sent_chksum = sent_packet[IP].chksum
        else:
            correct_sent_chksum = None
        if self.debug:
            print("actual sent checksum: ", sent_chksum)
            print("correct sent checksum: ", correct_sent_chksum)

        if self.dropped and IP not in sent_packet:
            reward = 0
            return reward
        if self.run == 1:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.chksum != calcChksum(), egr.egress_port == False,)
            if (sent_chksum != correct_sent_chksum) and not self.dropped:
                self.bug = True
                reward = 1
                if self.debug:
                    print("It was the incorrect sent checksum")
        elif self.run == 2:
            # egr.hdr.ipv4.chksum == calcChksum() &
            if (recv_chksum != correct_recv_cksum) and not self.dropped:
                self.bug = True
                reward = 1
                if self.debug:
                    print("It was the incorrect recv checksum")

        elif self.run == 3:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.ver != 4, egr.egress_port == False,)
            if (sent_version != 4 or recv_version != sent_version) and not self.dropped:
                self.bug = True
                reward = 1
                print("It was the wrong ip version")
                if self.debug:
                    print("It was the wrong ip version")

        elif self.run == 4:
            # (ing.hdr.ipv4 & [ing.hdr.ipv4.ihl < 4 | ing.hdr.ipv4.ihl > 15], egr.egress_port == False,)
            if sent_ihl < 5 and not self.dropped:
                self.bug = True
                reward = 1
                #if self.debug:
                print("It was the ihl out of bounds")

        elif self.run == 5:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.len != ing.hdr.ipv4.ihl * 4, egr.egress_port == False,)
            if ((sent_len < sent_ihl * 4) or (sent_len < 20)) and not self.dropped:
                self.bug = True
                reward = 1
                #if self.debug:
                print("It was the len != ihl*4, or len<20")

        elif self.run == 6:
            # (ing.hdr.ipv4 & ing.hdr.ipv4.ttl < 2, egr.egress_port == False,)
            if sent_ttl < 2 and not self.dropped:
                self.bug = True
                reward = 1
                if self.debug:
                    print("sent_ttl: ", sent_ttl)
                    print("recv_ttl: ", recv_ttl)
                    print("It was the sent_ttl")

        elif self.run == 7:
            # egr.hdr.ipv4.ttl == ing.hdr.ipv4.ttl - 1 &
            if (recv_ttl != sent_ttl - 1) and not self.dropped:
                self.bug = True
                reward = 1
                if self.debug:
                    print("sent_ttl: ", sent_ttl)
                    print("recv_ttl: ", recv_ttl)
                    print("It was the recv_ttl")

        elif self.run == 8:
            # egr.hdr.eth.srcAddr == ing.hdr.eth.dstAddr &
            if (recv_src_mac != sent_dst_mac) and not self.dropped:
                self.bug = True
                reward = 1

        elif self.run == 9:
            # egr.hdr.eth.dstAddr == table_val() &
            # egr.egress_port == table_val(),)
            try:
                if (ip_to_port[recv_dst_ip] != egr_port) and not self.dropped:
                    self.bug = True
                    reward = 1
                if (recv_dst_mac != port_to_mac[egr_port]) and not self.dropped:
                    self.bug = True
                    reward = 1
            except KeyError:
                if not self.dropped:
                    self.bug = True
                    reward = 1
                    if self.debug:
                        print("packet with invalid ip still forwarded")
        if self.bug:
            reward += 0
        else:
            reward = 0
        return reward

    def socket_server(self):
        if self.udp is None:
            print("udp is None")
        try:
            print("starting UDP server")
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp.bind((Host_IP, 9988))
        except:
            print("Nope the UDP socket could not be bound")

        input_ = [self.udp]
        verbose = self.debug
        def parse_packet(pkt):
            pkt = bytearray(pkt)
            if self.debug:
                print(pkt[0:4])
                print(pkt[4:])

            self.recv_port = struct.unpack('I', pkt[0:4])[0]
            pkt = Ether(bytes(pkt[4:]))
            if self.debug:
                print(pkt)
            self.received_packet = pkt
            if self.debug:
                pkt.show2()
        ######################## UDP and TCP corresponding clients ############################
        # UDP client to receive the messages
        # Parameters:
        #   Input:
        #   Output:
        class Client(Thread):
            def __init__(self, socket, address, sock_type):
                Thread.__init__(self)
                self.sock = socket
                self.addr = address
                self.type = sock_type
                self.start()

            def run(self):

                while 1:
                    if verbose:
                        print("Client sent:")
                    if self.type == "udp":
                        try:
                            msg, address = self.sock.recvfrom(1024)
                        except OSError:
                            msg = None
                            print("OS Error: ", OSError)

                        if verbose:
                            print("message:", msg)
                        if msg is None:
                            break
                        else:
                            parse_packet(msg)
                        break
                    else:
                        break
        if self.debug:
            print("server started and is listening")

        while 1:
            if self.udp is None:
                print("udp is None")
                break
            # check for TCP or UDP connection and call the right client
            s = None
            try:
                inputready, outputready, exceptready = select(input_, [], [])
                for s in inputready:
                    if s == self.udp:
                        Client(s, None, "udp")
            except KeyboardInterrupt:
                if s:  # <---
                    s.close()
                break  # <---
            except ValueError:
                print("Value error: ", ValueError)
                if s:  # <---
                    s.close()
                if self.udp:
                    self.udp.close()
                break  # <---

        print("shutdown and close executed")
        try:
            self.udp.close()
        except:
            return

class sshClient():
    def __init__(self, verbose):
        self.hostname = "127.0.0.1"
        self.password = "p4"
        self.command = None
        self.username = "p4"
        self.port = 2222
        self.client = None
        self.sent_packet = None
        self.debug = verbose

    def __del__(self):
        print("sshC deleted")

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy)
        self.client.connect(self.hostname, port=self.port, username=self.username, password=self.password)
    def disconnect(self):
        self.client.close()

    def send_packet(self, packet):
        if self.debug:
            print("SSHclient sent_chksum: ", packet[IP].chksum)
        self.sent_packet = packet
        packet = binascii.hexlify(bytes(packet))
        self.command = 'sudo ./tutorials/exercises/basic/send.py "%s"' % packet
        stdin, stdout, stderr = self.client.exec_command(self.command)
if __name__ == '__main__':
    main()
