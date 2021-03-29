#!/usr/bin/python3
import json
import sys
import os
import glob
import re
import ipaddress
#from scapy.all import *
import time
import argparse
import os
import sys
import dpdk_nic_bind
import dpdk_setup_ports
import yaml
import subprocess
import shlex
# sys.path.append('/root/v2.87/automation/trex_control_plane/examples/')
# import trex_root_path
sys.path.append('/opt/trex/current/trex_client/stf/examples/')
import stf_path
sys.path.append('/opt/trex/current/automation/trex_control_plane/interactive/')
sys.path.append('/opt/trex/current/automation/trex_control_plane/client_utils/')
sys.path.append('/opt/trex/current/automation/trex_control_plane/server/')
import outer_packages
sys.path.append('/opt/trex/current/automation/trex_control_plane/')
sys.path.append('/opt/trex/current/trex_client/stf/')
sys.path.append('/opt/trex/current/trex_client/stf/trex_stf_lib/')
sys.path.append('/opt/trex/current/trex_client/interactive/trex/examples/stl/')
import stl_path
sys.path.append('/opt/trex/current/automation/trex_control_plane/server/')
from trex_server import *
from trex.stl.api import *
from trex_stf_lib.trex_client import *
from trex_stf_lib.general_utils import *
from client_utils.trex_yaml_gen import *
from trex_stf_lib.trex_client import CTRexClient
from general_utils import *
from trex_yaml_gen import *
from pprint import pprint
from trex.astf.cap_handling import pcap_reader
from scapy.all import *
import os
import ipaddress
from time import sleep


class StfYaml(CTRexYaml):
    def add_pcap_file(self, local_pcap_path):
        new_pcap = dict(CTRexYaml.PCAP_TEMPLATE)
        # new_pcap['name'] = self.trex_files_path + os.path.basename(
        #                       local_pcap_path)
        new_pcap['name'] = self.trex_files_path + local_pcap_path
        self.yaml_obj[0]['cap_info'].append(new_pcap)
        if self.empty_cap:
            self.empty_cap = False
        self.file_list.append(local_pcap_path)
        return(len(self.yaml_obj[0]['cap_info']) - 1)

class STLImix(object):


    def mapping(self,testpmd_json):
                with open(testpmd_json,'r') as js:
                        self.pkt_mapping=json.load(js)
    def create_stream (self, pps, vm, src_mac, dst_mac, vlan=None, isg=0):
        print(vm)
        print(pps)
        size = 64
        if vlan == None:
          base_pkt = Ether(src=src_mac,dst=dst_mac)/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=32768,sport=1025)
        else:
          base_pkt = Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=vlan)/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=32768,sport=1025)
        pad = max(0, size - len(base_pkt)) * 'x'
        pkt = STLPktBuilder(pkt = base_pkt/pad,
                            vm = vm)

        return STLStream(isg = isg,
                         packet = pkt,
                         mode = STLTXCont(pps = pps*1000000*float(args.multiplier)))

    def get_streams (self, src_mac, dst_mac, vlan = None, qratio = [{'q': 0, 'pps': 10, 'isg':0}], testpmd_json='/tmp/testpmd.json',direction = 0, **kwargs):
        q = {}
        ql = {}
        #vm = [None] * len(STLImix.queue_ratio)
        vm = [None] * len(qratio)
        self.mapping(testpmd_json)
        for i in range(len(qratio)):
                  ql[qratio[i]['q']]=ql.get(qratio[i]['q'],0)+1
        for i in range(len(qratio)):
          print(i)
          indx=qratio[i]['q']
          q[indx]=q.get(indx,0)+1
          n=ql[indx]
          m=len(self.pkt_mapping[str(indx)])//ql[indx]
          j=q[indx]-1
          srclst=self.pkt_mapping[str(indx)][j * m:(j + 1) * m]
          vm[i] = STLScVmRaw([
              STLVmFlowVar(name = "dst_ip", value_list=srclst, op="inc"),
              STLVmWrFlowVar(fv_name='dst_ip', pkt_offset= 'IP.dst'),
              STLVmFixIpv4(offset = 'IP')
              ])
          print(i)
          print(vm[i])
        print(vm)
        return [self.create_stream( float(qratio[i]['pps']), vm[i], src_mac, dst_mac, vlan) for i in range(len(qratio))]

def register():
    return STLImix()

def gen_learning_pkt(pps, pcap_file, start_pkt=0):
    if not pcap_file:
        gen_scapy_pkt(pps,'UDP',start_seq=start_pkt)
    else:
        sport, dport = parse_pcap(pcap_file)
        gen_scapy_pkt(pps,'TCP',start_seq=start_pkt,src_port=sport,dst_port=dport)
    # elif len(stf_file) > 1:
    #    for capf in stf_file:
    #        print(os.path.abspath(os.path.relpath(stf_path+capf)))
    #        src_port, dst_port = parse_pcap()
    #        gen_scapy_pkt()


def parse_pcap(pcap_file):
    cap = pcap_reader(os.path.abspath(os.path.relpath(pcap_file)))
    cap.analyze()
    print(cap.s_port)
    print(cap.d_port)
    return cap.s_port,cap.d_port

def get_qjson():
    maxpps=[]
    if  args.qratio:
      for i in range(len(args.qratio)):
        qratio=json.loads(args.qratio[i])
        maxpps.append(qratio)
    else:
      with open(args.ratio_file) as f:
        maxpps = json.load(f)
    print(maxpps)
    return maxpps


def get_maxpps(qjson):
    print(qjson)
    maxpps=[]
    for i in range(len(qjson)):
        print(qjson[i])
        qratio=json.loads(qjson[i])
        maxpps.append(qratio['pps'])
    maxpps.sort()
    return maxpps[-1]

def get_qratio(qjson):
    print(qjson)
    maxpps=[]
    for i in range(len(qjson)):
        qratio=json.loads(qjson[i])
        maxpps.append(qratio)
    print(maxpps)
    return maxpps


def trex_cfg():
    try:
        stream = open('/etc/trex_cfg.yaml', 'r')
        cfg_dict= yaml.safe_load(stream)
    except Exception as e:
        print(e);
        raise e

    devices=[]
    for i in range(len(cfg_dict[0]['port_info'])):
        devices.append({'name':args.interfaces[i]})
        devices[i]['dest_mac']=cfg_dict[0]['port_info'][i]['dest_mac']
        devices[i]['src_mac']=cfg_dict[0]['port_info'][i]['src_mac']
        if cfg_dict[0]['port_info'][i].get('vlan'):
          devices[i]['vlan']=cfg_dict[0]['port_info'][i]['vlan']
    return devices

def gen_scapy_pkt(maxpps, proto, start_seq=0, src_port=1025, dst_port=32768):
    devices=trex_cfg()
    ip_start =str(ipaddress.IPv4Address('48.0.0.1')+start_seq)
    size = 65 
    end_seq = maxpps if maxpps-start_seq <= 10 else 10
    iter=0
    for i in range(start_seq, end_seq):
        print(str(ipaddress.IPv4Address(ip_start)+iter))
        if devices[0].get('vlan'):
            pkt2 = Ether(src=devices[0]['src_mac'],dst=devices[0]['dest_mac'])/Dot1Q(vlan=int(devices[0]['vlan']))
        else:
            pkt2 = Ether(src=devices[0]['src_mac'],dst=devices[0]['dest_mac'])
        pkt1 = pkt2/IP(dst=str(ipaddress.IPv4Address(ip_start)+iter),src="16.0.0.1")
        if proto == 'UDP':
            pkt = pkt1/UDP(dport=dst_port,sport=src_port)
        else:
            pkt = pkt1/TCP(dport=dst_port,sport=src_port)
        data = (max(0, size - len(pkt))+i) * 'x'
        sendp(pkt/data, iface=args.interfaces[0])
        iter=iter+1
        sleep(0.05)


def parse_testpmd_log(mpps,pcap_file='',start=0):
    devices=trex_cfg()
    src_mac = devices[0]['src_mac']
    q = {}
    ip_start = str(ipaddress.IPv4Address('48.0.0.1')+start)
    for i in range(start,mpps,10):
        end=mpps if mpps < i+10 else i+10
        print('/tmp/testpmd{src}{seq}.log'.format(seq=i,src=pcap_file))
        with open('/tmp/testpmd{src}{seq}.log'.format(seq=i,src=pcap_file), 'r') as tp:
            for ln in tp:
                x = re.search('src='+src_mac.upper(), ln)
                if x:
                    y = re.search('(Receive queue|RSS queue)=0x\d+', ln)
                    if y:
                        q[int(y.group().split('=')[1], 16)] = q.get(int(
                        y.group().split('=')[1], 16), [])+[int(
                        ipaddress.IPv4Address(ip_start)+(int(re.search(
                        'length=\d+', ln).group().split('=')[1])-65))]
    for key in q.keys():
        q[key]=list(set(q[key]))
    print(q)
    json_file='/tmp/testpmd{src}.json'.format(src=pcap_file)
    dump_queue_map(q,json_file)
    #print(get_queue_map())
    return q

def dump_queue_map(q,json_file='/tmp/testpmd.json'):
    with open(json_file, 'w') as js:
        json.dump(q, js, indent=4)

def get_queue_map(testpmd_json='/tmp/testpmd.json'):
            print(testpmd_json)
            with open(testpmd_json,'r') as js:
                    pkt_mapping=json.load(js)
            return pkt_mapping

def gen_stf_yaml(imix_table,b,pcap):
    #trex = CTRexClient('127.0.0.1')
    #imix_table=qmap(os.path.basename(pcap[1]))
    yaml_obj = StfYaml('./')
    ql={}
    q={}
    yaml_obj.set_generator_param('clients_start', '16.0.0.1')
    yaml_obj.set_generator_param('clients_end', '16.0.0.1')
    yaml_obj.set_generator_param('servers_start', '48.0.0.1')
    yaml_obj.set_generator_param('servers_end', '48.0.0.10')
    for i in range(len(imix_table)):
        ql[imix_table[i]['q']] = ql.get(imix_table[i]['q'], 0)+1
    for i in range(len(imix_table)):
        indx = imix_table[i]['q']
        q[indx] = q.get(indx, 0)+1
        n = ql[indx]
        m = len(b[str(indx)])//ql[indx]
        i = q[indx]-1
        # print(b[str(indx)][i * m:(i + 1) * m])
        tlst = b[str(indx)][i * m:(i + 1) * m]
        # print('iplist %s'%tlst)
        # print('newpps %s'%(imix_table[i]['pps']/len(tlst)))
        npps = float(imix_table[i]['pps'])/len(tlst)
        for z in range(len(tlst)):
            #print(tlst[i])
            for j in range(len(pcap)):
                # print(pcap[j])
                # print('pps %s'%(npps/len(pcap)))
                cps = npps/len(pcap)
                ret_idx1 = yaml_obj.add_pcap_file(stf_path+pcap[j])
                yaml_obj.set_cap_info_param('cps', cps, ret_idx1)
                yaml_obj.set_cap_info_param('keep_src_port', 'true', ret_idx1)
                yaml_obj.set_cap_info_param('server_addr', str(ipaddress.IPv4Address(tlst[z])), ret_idx1)
                yaml_obj.set_cap_info_param('one_app_server', 'true', ret_idx1)

    yaml_obj.empty_cap = False
    # print(yaml_obj.dump())
    yaml_obj.to_yaml('mydns_traffic.yaml')


def gen_stl(queue_ratio):
    c = STLClient(verbose_level="error")
    passed = True
    try:
        devices=trex_cfg()
        c.connect()
        my_ports = [0, 1]
        c.reset(ports=my_ports)
        c.remove_all_streams(my_ports)
        c.add_streams(register().get_streams(devices[0]['src_mac'],devices[0]['dest_mac'],int(devices[0].get('vlan')),testpmd_json='/tmp/testpmd.json',qratio=queue_ratio), ports = [0])
        #5000000
        c.start(ports = [0], mult = "1", duration = int(args.duration))
        c.wait_on_traffic(ports = [0, 1])
    except STLError as e:
        passed = False
        print(e)
    finally:
        c.disconnect()


def gen_stf():
    trex = CTRexClient('127.0.0.1')
    print("Before Running, TRex status is: %s", trex.is_running())
    print("Before Running, TRex status is: %s",
          trex.get_running_status())
    ret = trex.start_trex(c=1, m=0.1, d=int(args.duration), f='mydns_traffic.yaml',
                          nc=True)

    print("After Starting, TRex status is: %s %s", trex.is_running(),
          trex.get_running_status())
    time.sleep(int(args.duration))
    while trex.is_running():
      time.sleep(5)
    print("Is TRex running? %s %s", trex.is_running(),
          trex.get_running_status())

def gen_pkt_copy_log(start_pkt,end,pcap_file):
    flush_log = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null  {user}@{host} "echo \'\'>{src}"'.format( user  = args.dut_user, host  = args.dut_host, src  = testpmd_log)
    os.system(flush_log)
    gen_learning_pkt(end,pcap_file,start_pkt)
    sleep(1)
    scp_log = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host}:{src} /tmp/testpmd{dest}{seq}.log'.format( user  = args.dut_user, host  = args.dut_host, src  = testpmd_log, dest = os.path.basename(pcap_file), seq = start_pkt)
    os.system(scp_log)


def main():
    devices=trex_cfg()
    obj = dpdk_setup_ports.CIfMap(dpdk_setup_ports.map_driver.cfg_file);
    obj.do_return_to_linux()
    for i in  args.interfaces:
        ifdown='ifconfig {nic} up'.format(nic=i)
        os.system(ifdown)
    cmdline='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host} "echo \'port config all rss all\nset fwd rxonly\nset verbose 1\nstart\'>/tmp/cmdline"'.format( user  = args.dut_user, host  = args.dut_host)
    os.system(cmdline)
    testpmd='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host} "{testpmd} -l 0,1,2,3,4,5,6 --socket-mem 7168 -- -i --nb-cores=6   --rxq={qnum}   --txq={qnum}  --forward-mode=mac   --eth-peer=0,{nic1}   --eth-peer=1,{nic2} --rxd=1024 --txd=1024 --cmdline-file=/tmp/cmdline 1>/tmp/testpmd.log"'.format( user  = args.dut_user, host  = args.dut_host, testpmd =  args.testpmd_path, nic1 = devices[0]['src_mac'], nic2 = devices[1]['src_mac'], qnum = args.q_num)
    ps=subprocess.Popen(testpmd,shell=True) 
    sleep(5)
    fileList = glob.glob('/tmp/testpmd*.log')
    for filepath in fileList:
        os.remove(filepath)
    if stf_file == []:
        pcap_file = ''
    elif len(stf_file) == 1:
        pcap_file = stf_file[0]
    for i in range(0,mpps,10):
        end=mpps if mpps < i+10 else i+10
        if stf_file != []:
            for pcap_file in stf_file:
                gen_pkt_copy_log(i,end,stf_path+pcap_file)
        else:
            gen_pkt_copy_log(i,end,pcap_file)
            print('copy testpmd')
    sleep(5)
    ps.terminate()
    cmd = '{ptn} dpdk_nic_bind.py -b vfio-pci eth1 eth2'.format( ptn = sys.executable)
    os.system(cmd)
    testpmd='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host} "{testpmd}  -l 0,1,2,3,4,5,6 --socket-mem 7168 -- -i -a  --nb-cores=6   --rxq={qnum}   --txq={qnum}   --forward-mode=macswap --eth-peer=0,{nic1}   --eth-peer=1,{nic2} --rxd=1024 --txd=1024  1>/tmp/testpmd.log"'.format( user  = args.dut_user, host  = args.dut_host, testpmd =  args.testpmd_path, nic1 = devices[0]['src_mac'], nic2 = devices[1]['src_mac'], qnum = args.q_num)
    ps=subprocess.Popen(testpmd,shell=True) 
    if stf_file == []:
        outF = open('/tmp/trex.log', "w")
        cmd = './t-rex-64 -c 6  -i  --iom 0 --no-key'  
        trexps=subprocess.Popen(cmd,shell=True,stdout=outF)
    else:
        os.system('./daemon_server start') 
    sleep(5)
    qratio=get_qjson()
    gen_traffic(qratio)
    for i in range(len(qratio)):
      qratio[i]['pps']= 0.1 if 1-float(qratio[i]['pps']) == 0 else 1-float(qratio[i]['pps'])
    gen_traffic(qratio)
    ps.terminate()
    if stf_file == []:
        trexps.terminate()
        print(os.system("ps axo pid,args|grep rex"))
        #os.system("kill -9 `ps axo pid,args|grep rex|cut -f 2 -d ' '|head -n 1`")
        outF.close()
        trexps.wait()
        print(os.system("ps axo pid,args|grep rex"))
        os.system("kill -9 `ps axo pid,args|grep rex|cut -f 2 -d ' '|head -n 1`")
    else:
        os.system('./daemon_server stop')
    sleep(5)
    print(os.system("ps axo pid,args|grep rex"))

def gen_traffic(qratio):
    #qratio=get_qratio(args.qratio)
    #qratio=get_qjson()
    qmap={}
    if len(stf_file) != 0:
        for stf_pcap in stf_file:
            parse_testpmd_log(mpps,os.path.basename(stf_pcap),start=0)
            #qmap[os.path.basename(stf_pcap)]=get_queue_map('/tmp/testpmd{src}.json'.format(src=os.path.basename(stf_pcap)))
            qmap=get_queue_map('/tmp/testpmd{src}.json'.format(src=os.path.basename(stf_pcap)))
            gen_stf_yaml(qratio,qmap,[stf_pcap])
        gen_stf()
    else:
        parse_testpmd_log(mpps,start=0)
        qmap=get_queue_map()
        gen_stl(qratio)

def gen_learning():
    testpmd_log='/tmp/testpmd.log'
    if stf_file == []:
        pcap_file = ''
    elif len(stf_file) == 1:
        pcap_file = stf_file[0]
    gen_learning_pkt(int(args.gen_learning[1]),pcap_file,start_pkt=int(args.gen_learning[0]))
#    cmd = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host}:{src} /tmp/testpmd{dest}{seq}.log'.format( user  = args.dut_user, host  = args.dut_host, src  = testpmd_log, dest = os.path.basename(pcap_file), seq = args.gen_learning[0])
#    print(cmd)
#    os.system(cmd)

if __name__ == '__main__':
    stf_file = []
    parser = argparse.ArgumentParser()
    parser.add_argument("--interfaces", nargs='*', default=[], action='store')
    parser.add_argument("--learning-phase", nargs='*', default=[], action='store')
    parser.add_argument("--qratio", nargs='*', default=[], action='store')
    parser.add_argument("--ratio-file",  action='store')
    parser.add_argument("--fps",  action='store')
    parser.add_argument("--dut-user", default='root', action='store')
    parser.add_argument("--dut-host", default=None, action='store')
    parser.add_argument("--testpmd-path", default=None, action='store')
    parser.add_argument("--q-num", default=2, action='store')
    parser.add_argument("--stf-path", default=None, action='store')
    parser.add_argument("--duration", default=30, action='store')
    parser.add_argument("--multiplier", default=5, action='store')
    parser.add_argument("--gen-traffic", action='store_true')
    parser.add_argument("--gen-learning",nargs='*',default=[], action='store')
    args = parser.parse_args()
    try:
        stf_path = ''
        if args.stf_path is not None:
            stf_path = args.stf_path
        if os.path.isdir(stf_path):
            stf_file = os.listdir(stf_path)
            stf_file = [f for f in os.listdir(stf_path)
                        if re.match(r'.*\.pcap$', f)]
        elif os.path.isfile(stf_path):
            stf_file.append(stf_path)
            stf_path = ''
        print(stf_file)
    except (IndexError, KeyError):
        print("Expect a json input with queue distribution ratio and "
              "location of pcap for STF traffic")
    # check nic bound to kernel
    qjson=get_qjson()
    mpps=int(args.fps)
    c=0
    testpmd_log='/tmp/testpmd.log'
    testpmd_json={}
    #parse_testpmd_log(mpps,start=0)
    if stf_file == []:
        pcap_file = ''
    elif len(stf_file) == 1:
        pcap_file = stf_file[0]
  
    #obj = dpdk_setup_ports.CIfMap(dpdk_setup_ports.map_driver.cfg_file);
    #obj.do_return_to_linux()
    #for i in  args.interfaces:
    #    ifdown='ifconfig {nic} up'.format(nic=i)
    #    os.system(ifdown)
    if not args.gen_traffic and args.gen_learning == []: 
        obj = dpdk_setup_ports.CIfMap(dpdk_setup_ports.map_driver.cfg_file);
        obj.do_return_to_linux()
        for i in  args.interfaces:
            ifdown='ifconfig {nic} up'.format(nic=i)
            os.system(ifdown)
        main()
    if args.gen_traffic:
        qratio=get_qjson()
        gen_traffic(qratio)
        for i in range(len(qratio)):
          qratio[i]['pps']= 0.1 if 1-float(qratio[i]['pps']) == 0 else 1-float(qratio[i]['pps'])
        print(qratio)
        #gen_traffic(qratio)
    if args.gen_learning != []:
        gen_learning()
