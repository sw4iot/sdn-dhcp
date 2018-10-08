# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# a simple ICMP Echo Responder

import os
import json
import requests_unixsocket

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import addrconv, dpid as dpid_lib
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_3
from webob import Response

from netaddr import IPNetwork, IPAddress

class DHCPResponder(app_manager.RyuApp):
    """
    use example
        self.switches = {
            '81474781969487': {
                'tenantID: 'tenant1'
                'ipaddress': '192.168.1.1',
                'netmask': '255.255.255.0',
                'address': '0a:e4:1c:d1:3e:44',
                'dns': '8.8.8.8',
                'hosts': {
                    '00:00:00:d3:fc:57': {
                        'id:iot-device_1,
                        'endpointID': '0cc175b9c0f1b6a831c399e269772661',
                        'hostname': 'huehuehue',
                        'netID': 'tenant1-net',
                        'groupID': '',
                        'dns': '8.8.8.8',
                        'ipaddress':  '192.168.1.2',
                    }
                },
                'available_address': [
                    '192.168.1.10',
                    '192.168.1.20'
                ]

            }}
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(DHCPResponder, self).__init__(*args, **kwargs)
        self.acks = {}
        self.switches = {}
        self.switches = {
            81713664287054: {
                'tenantID': 'tenant1',
                'ipaddress': '30.1.1.1',
                'netmask': '255.255.255.0',
                'address': '0a:e4:1c:d1:3e:44',
                'dns': '8.8.8.8',
                'hosts': {
                    '92:e5:97:98:e8:6a': {
                        'id':'iot-device_1',
                        'endpointID': '0cc175b9c0f1b6a831c399e269772661',
                        'hostname': 'sw4iot-master-dev',
                        'netID': 'tenant1-net',
                        'groupID': '',
                        'dns': '8.8.8.8',
                        'ipaddress':  '192.168.1.2',
                    }
                },
                'available_address': [
                    '192.168.1.10',
                    '192.168.1.20'
                ]
            }}
        
        wsgi = kwargs['wsgi']
        wsgi.register(DHCPController,
                      {'dhcp_server': self})

        if os.path.exists("/run/contiv/contiv-cni.sock"):
            self.session = requests_unixsocket.Session()
            self.logger.info("CONNECTED TO CONTIV!")
        else:
             self.logger.info("COULDN'T CONNECT WITH CONTIV!")
             exit(1)

    def get_ip_from_contiv(self, tenantID, host):
        contiv_url = "http+unix://%2Fvar%2Frun%2Fcontiv%2Fcontiv-cni.sock/ContivIOT.AddIotDev"
        data = {
            "IOT_DEV_NAME": host['id'],
            "IOT_DEV_TENANT": tenantID,
            "IOT_DEV_INFRA_ID": host['endpointID'],
            "IOT_DEV_NETWORK": host['netID'],
            "IOT_DEV_GROUP": host['groupID']
        }
        
        response = self.session.post(contiv_url, json=data)
        if response.status_code == 200:
            self.logger.info("REQ TO CONTIV OK! %s", response.text)
            result = response.json()
            return result['epattr']['ipaddress']
        else:
            return None

    def get_server_info(self, datapath):
        if datapath in self.switches:
            ipaddress = addrconv.ipv4.text_to_bin(
                self.switches[datapath]['ipaddress'])
            netmask = addrconv.ipv4.text_to_bin(
                self.switches[datapath]['netmask'])
            address = str(self.switches[datapath]['address'])
            return ipaddress, netmask, address, str(self.switches[datapath]['ipaddress'])
        return None, None, None, None

    def get_host_info(self, datapath, hostaddress):
        ipaddress = hostname = dns = None
        if datapath in self.switches:
            if hostaddress in self.acks:
                info = self.acks[hostaddress]
                return str(info['ipaddress']), str(info['hostname']), info['dns']

            if hostaddress in self.switches[datapath]['hosts']:
                confhost = self.switches[datapath]['hosts'][hostaddress]
                
                ipaddress = str(self.get_ip_from_contiv(
                    self.switches[datapath]['tenantID'], confhost)) #str(confhost['ipaddress'])
                
                hostname = str(confhost['hostname'])
                dns = addrconv.ipv4.text_to_bin(confhost['dns'])
            if not ipaddress and self.switches[datapath]['available_address']:
                ipaddress = str(
                    self.switches[datapath]['available_address'].pop())
                num = ipaddress.split('.')[-1]
                hostname = str("machine" + num)
                dns = addrconv.ipv4.text_to_bin(self.switches[datapath]['dns'])
                self.acks[hostaddress] = {
                    'ipaddress': str(ipaddress),
                    'hostname': str(hostname),
                    'dns': dns
                }
        return ipaddress, hostname, dns

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER
                                          )]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod67 = parser.OFPFlowMod(datapath=datapath,
                                  priority=32760,
                                  match=parser.OFPMatch(
                                      eth_type=0x0800, ip_proto=17, udp_dst=67),
                                  instructions=inst)
        mod68 = parser.OFPFlowMod(datapath=datapath,
                                  priority=32760,
                                  match=parser.OFPMatch(
                                      eth_type=0x0800, ip_proto=17, udp_dst=68),
                                  instructions=inst)

        req = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 1500)
        datapath.send_msg(req)
        datapath.send_msg(mod67)
        datapath.send_msg(mod68)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
        
        if pkt_dhcp:
            if datapath.id in self.switches:
                self._handle_dhcp(datapath, port, pkt)

    def assemble_ack(self, pkt, datapath):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req = pkt.get_protocol(dhcp.dhcp)

        ipaddress, netmask, address, dhcpip = self.get_server_info(datapath)
        hostipaddress, hostname, dns = self.get_host_info(datapath,
                                                          req_eth.src)
        
        if ipaddress:
            req.options.option_list.remove(
                next(opt for opt in req.options.option_list if opt.tag == 53))
            req.options.option_list.insert(
                0, dhcp.option(tag=51, value='8640'))
            req.options.option_list.insert(
                0, dhcp.option(tag=1, value=netmask))
            req.options.option_list.insert(
                0, dhcp.option(tag=3, value=ipaddress))
            req.options.option_list.insert(
                0, dhcp.option(tag=6, value=dns))
            req.options.option_list.insert(
                0, dhcp.option(tag=12, value=hostname))
            req.options.option_list.insert(
                0, dhcp.option(tag=54, value=ipaddress))
            req.options.option_list.insert(
                0, dhcp.option(tag=53, value='05'.decode('hex')))

            ack_pkt = packet.Packet()
            ack_pkt.add_protocol(ethernet.ethernet(
                ethertype=req_eth.ethertype, dst=req_eth.src, src=address))
            ack_pkt.add_protocol(
                ipv4.ipv4(dst=req_ipv4.dst, src=dhcpip, proto=req_ipv4.proto))
            ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
            ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                           siaddr=dhcpip,
                                           boot_file=req.boot_file,
                                           yiaddr=hostipaddress[:-3],  # to remove /24
                                           xid=req.xid,
                                           options=req.options))
            self.logger.info("ASSEMBLED ACK: %s -> %s" %
                             (req_eth.src, hostipaddress))
        print "PKT ACK", ack_pkt
        return ack_pkt

    def assemble_offer(self, pkt, datapath):
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc = pkt.get_protocol(dhcp.dhcp)
        offer_pkt = None
        ipaddress, netmask, address, dhcpip = self.get_server_info(datapath)
        hostipaddress, hostname, dns = self.get_host_info(
            datapath, disc_eth.src)
        
        if ipaddress:
            disc.options.option_list.remove(
                next(opt for opt in disc.options.option_list if opt.tag == 55))
            disc.options.option_list.remove(
                next(opt for opt in disc.options.option_list if opt.tag == 53))
            disc.options.option_list.remove(
                next(opt for opt in disc.options.option_list if opt.tag == 12))
            disc.options.option_list.insert(
                0, dhcp.option(tag=1, value=netmask))
            disc.options.option_list.insert(
                0, dhcp.option(tag=3, value=ipaddress))
            disc.options.option_list.insert(
                0, dhcp.option(tag=6, value=dns))
            disc.options.option_list.insert(
                0, dhcp.option(tag=12, value=hostname))
            disc.options.option_list.insert(
                0, dhcp.option(tag=53, value='02'.decode('hex')))
            disc.options.option_list.insert(
                0, dhcp.option(tag=54, value=ipaddress))
            offer_pkt = packet.Packet()
            offer_pkt.add_protocol(ethernet.ethernet(
                ethertype=disc_eth.ethertype, dst=disc_eth.src, src=address))
            offer_pkt.add_protocol(
                ipv4.ipv4(dst=disc_ipv4.dst, src=dhcpip, proto=disc_ipv4.proto))
            offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
            offer_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=disc_eth.src,
                                             siaddr=dhcpip,
                                             boot_file=disc.boot_file,
                                             yiaddr=hostipaddress[:-3],   # to remove /24
                                             xid=disc.xid,
                                             options=disc.options))

            self.logger.info("ASSEMBLED OFFER: %s --> %s" %
                             (disc_eth.src, hostipaddress))
        #print offer_pkt
        return offer_pkt

    def get_state(self, pkt_dhcp):
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    def _handle_dhcp(self, datapath, port, pkt):

        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = self.get_state(pkt_dhcp)
        self.logger.info("NEW DHCP %s PACKET RECEIVED: %s, %s" %
                         (dhcp_state, pkt_dhcp.chaddr, dhcp_state))

        if dhcp_state == 'DHCPDISCOVER':
            discover = self.assemble_offer(pkt, datapath.id)
            if discover:
                self._send_packet(datapath, port, discover)
        elif dhcp_state == 'DHCPREQUEST':
            ack = self.assemble_ack(pkt, datapath.id)
            if ack:
                self._send_packet(datapath, port, ack)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


class DHCPController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(DHCPController, self).__init__(req, link, data, **config)
        self.dhcp_server = data['dhcp_server']

    @route('dhcp', '/dhcp/all', methods=['GET'])
    def get_dhcp_info(self, req, **kwargs):
        body = json.dumps(self.dhcp_server.switches)
        return Response(content_type='application/json', body=body)

    @route('dhcp', '/dhcp/{dpid}', methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_dhcp_switch_info(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in self.dhcp_server.switches:
            return Response(status=404)

        body = json.dumps(self.dhcp_server.switches[dpid])
        return Response(content_type='application/json', body=body)

    @route('dhcp', '/dhcp/add/{dpid}', methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def insert_dhcp_netinformation(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            return Response(status=400)
        if new_entry:
            dns = '8.8.8.8'
            for field in ["ipaddress", "netmask", "address"]:
                if field not in new_entry:
                    return Response(status=400)

            if 'dns' in new_entry:
                dns = new_entry['dns']

            available_address = []
            if 'startip' in new_entry and 'endip' in new_entry:
                startip = int(new_entry['startip'].split('.')[-1])
                endip = int(new_entry['endip'].split('.')[-1])
                base = ".".join(new_entry['startip'].split('.')[:-1])
                if startip >= endip:
                    return Response(status=400)
                for i in range(startip, endip + 1):
                    available_address.append(base + "." + "%02.0f" % (i))

            if dpid not in self.dhcp_server.switches:
                self.dhcp_server.switches[dpid] = {
                    "available_address": available_address,
                    "hosts": {}
                }

            self.dhcp_server.switches[dpid][
                'ipaddress'] = new_entry['ipaddress']
            self.dhcp_server.switches[dpid]['netmask'] = new_entry['netmask']
            self.dhcp_server.switches[dpid]['address'] = new_entry['address']
            self.dhcp_server.switches[dpid]['dns'] = dns
            body = json.dumps(self.dhcp_server.switches[dpid])
            return Response(content_type='application/json', body=body)
        return Response(status=404)

    @route('dhcp', '/dhcp/host/{dpid}', methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def insert_dhcp_hostinformation(self, req, **kwargs):
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        
        if dpid in self.dhcp_server.switches:
            try:
                new_entry = req.json if req.body else {}
            except ValueError:
                return Response(status=400)
            if new_entry:
                dns = self.dhcp_server.switches[dpid]['dns']
                for field in ["ipaddress", 'hostname', "address"]:
                    if field not in new_entry:
                        return Response(status=400)

                if 'dns' in new_entry:
                    dns = new_entry['dns']

                if new_entry["address"] not in self.dhcp_server.switches[dpid]['hosts']:
                    self.dhcp_server.switches[dpid][
                        'hosts'][new_entry["address"]] = {'dns': dns}

                self.dhcp_server.switches[dpid]['hosts'][
                    "ipaddress"] = new_entry['ipaddress']

                self.dhcp_server.switches[dpid][
                    'hosts']['hostname'] = new_entry['hostname']

                body = json.dumps(self.dhcp_server.switches[dpid])
                return Response(content_type='application/json', body=body)
        return Response(status=404)
