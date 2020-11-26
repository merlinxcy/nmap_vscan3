#! coding:utf-8
# Author: xuchenyi
# 使用nmap自带的指纹去除nmap特征后进行服务识别,识别思路是先进行一次socket连接,接受服务器的welcome banner
# 如果welcome banner在设置的一定时间内没有收到,那么根据常见端口发送探测报文
# 如果还是没有根据nmap probe中的数据逐条发送数据
# 如果不在指纹库中的最后就返回unkown的结果

import os
import re
import json
import codecs
import socket
import traceback
import contextlib
import threading
import asyncio


SOCKET_TIMEOUT = 2 # 等待welcome banner的超时,5秒
SOCKET_READ_BUFFERSIZE = 1024 # 接受banner的缓冲区


class ServiceScanException(Exception):
    pass


class ServiceProbe(object):
    """
    解析 nmap - service - probes 文件
    """
    def __init__(self):
        self.probe_raw_filename = os.path.dirname(os.path.realpath(__file__)) + '/nmap-service-probes'
        self.probe_json_filename = os.path.dirname(os.path.realpath(__file__)) + '/nmap-service-probes.json'
        self.data = self.parse()

    def parse(self):
        if not os.path.exists(self.probe_json_filename):
            r = self.get_probe_raw_file()
            json.dump(r, open(self.probe_json_filename,'w'))
            return r
        else:
            return json.load(open(self.probe_json_filename,'r'))

    def get_probe_raw_file(self):
        if not os.path.exists(self.probe_raw_filename):
           raise ServiceScanException('Fail to open file %s' % self.probe_raw_filename)

        lines = []
        with open(self.probe_raw_filename, 'r',encoding="utf-8") as fp:
            for line in fp:
                # 不去读取注释
                if line.startswith('\n') or line.startswith('#'):
                    continue
                lines.append(line)
        self.isvalid_nmap_service_probe_file(lines)
        return self.parse_nmap_service_probes(lines)

    def isvalid_nmap_service_probe_file(self, lines):
        """
        确认nmap probe是否正确
        :param lines:
        :return:
        """
        if not lines:
            raise ServiceScanException("Failed to read file")
        c = 0
        for line in lines:
            if line.startswith("Exclude "):
                c += 1
            if c > 1:
                raise ServiceScanException("Only 1 Exclude allowed")
            l = lines[0]
            if not(l.startswith("Exclude ") or l.startswith("Probe ")):
                raise ServiceScanException("Parse error on nmap-service-probes file")

    def parse_nmap_service_probes(self, lines):
        """
        parse probes的文件
        :param lines:
        :return:
        """
        data = "".join(lines)
        probes_parts = data.split("\nProbe ")
        _ = probes_parts.pop(0)
        if _.startswith("Exclude "):
            g_exclude_directive = _
        #根据Probe分割,循环读取service指纹
        return [
            self.parse_nmap_service_probe(probe_part)
            for probe_part in probes_parts
        ]

    def parse_nmap_service_probe(self, data):
        probe = {}
        lines = data.split("\n")

        probestr = lines.pop(0)
        probe["probe"] = self.get_probe(probestr)

        matches = []
        softmatches = []

        for line in lines:
            if line.startswith("match "):
                match = self.get_match(line)
                if match not in matches:
                    matches.append(match)

            elif line.startswith("softmatch "):
                softmatch = self.get_softmatch(line)
                if softmatch not in softmatches:
                    softmatches.append(softmatch)

            elif line.startswith("ports "):
                probe["ports"] = self.get_ports(line)

            elif line.startswith("sslports "):
                probe["sslports"] = self.get_ssloirts(line)

            elif line.startswith("totalwaitms "):
                probe["totalwaitms"] = self.get_totalwaitms(line)

            elif line.startswith("tcpwrappedms "):
                probe["tcpwrappedms"] = self.get_tcpwrappedms(line)

            elif line.startswith("rarity "):
                probe["rarity"] = self.get_rarity(line)

            elif line.startswith("fallback "):
                probe["fallback"] = self.get_fallback(line)

        probe['matches'] = matches
        probe['softmatches'] = softmatches

        return probe
    #####################################################
    # 解析
    def parse_directive_syntax(self, data):
        """
        获取语法数据
        <directive_name><blank_space><flag><delimiter><directive_str><flag>
        :param data:
        :return:
        """
        if data.count(" ") <= 0:
            raise ServiceScanException("nmap-service-probes - error directive format")

        blank_index = data.index(" ")
        directive_name = data[:blank_index]
        blank_space = data[blank_index: blank_index + 1]
        flag = data[blank_index + 1: blank_index + 2]
        delimiter = data[blank_index + 2: blank_index +3]
        directive_str = data[blank_index+3:]

        directive = {
            "directive_name": directive_name,
            "flag": flag,
            "delimiter": delimiter,
            "directive_str": directive_str
        }
        return directive


    def get_probe(self, data):
        """
        得到probe格式
        Format: [Proto][probename][blank_space][q][delimiter][probestring]
        NULL q||
        GenericLines q|\r\n\r\n|
        :param data:
        :return:
        """
        proto = data[:4]
        other = data[4:]
        if proto not in ["TCP ", "UDP "]:
            raise ServiceScanException("Probe <protocol> must be either TCP or UDP")

        if not (other and other[0].isalpha()):
            raise ServiceScanException("nmap-service-probes - bad probe name")

        directive = self.parse_directive_syntax(other)

        probename = directive.get("directive_name")
        probestring, _ = directive.get("directive_str").split(directive.get("delimiter"),1)

        probe = {
            "protocol": proto.strip(),
            "probename": probename,
            "probestring": probestring
        }

        return probe

    def get_match(self, data):
        """
        Syntax: match <service> <pattern> [<versioninfo>]
        :param data:
        :return:
        """
        matchtext = data[len("match") + 1:]
        directive = self.parse_directive_syntax(matchtext)

        pattern, versioninfo = directive.get("directive_str").split(
            directive.get("delimiter"), 1
        )
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            pattern_compiled = pattern
        except Exception as err:
            pattern_compiled = ''
        record = {
            "service": directive.get("directive_name"),
            "pattern": pattern,
            "pattern_compiled": pattern_compiled,
            "versioninfo": versioninfo
        }
        return record

    def get_softmatch(self, data):
        """
        Syntax: softmatch <service> <pattern>
        :param data:
        :return:
        """
        matchtext = data[len("softmatch") + 1:]
        directive = self.parse_directive_syntax(matchtext)
        pattern, _  = directive.get("directive_str").split(
            directive.get("delimiter"),1
        )
        try:
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            pattern_compiled = pattern
        except:
            pattern_compiled = ''

        record = {
            "service": directive.get("directive_name"),
            "pattern": pattern,
            "pattern_compiled": pattern_compiled # 序列化
        }

        return record

    def get_ports(self, data):
        """

        :param data:
        :return:
        """
        ports = data[len("ports") + 1 :]
        record = {
            "ports": ports
        }
        return record

    def get_ssloirts(self, data):
        """

        :param data:
        :return:
        """
        sslports = data[len("sslports") + 1:]
        record = {
            "sslports" : sslports
        }
        return record

    def get_totalwaitms(self, data):
        totalwaitms = data[len("totalwaitms") + 1:]
        record = {
            "totalwaitms": totalwaitms
        }
        return record

    def get_tcpwrappedms(self, data):
        # Syntax: tcpwrappedms <milliseconds>
        tcpwrappedms = data[len("tcpwrappedms") + 1:]
        record = {
            "tcpwrappedms": tcpwrappedms
        }

        return record

    def get_rarity(self, data):
        # Syntax: rarity <value between 1 and 9>
        # Syntax: tcpwrappedms <milliseconds>
        rarity = data[len("rarity") + 1:]
        record = {
            "rarity": rarity
        }

        return record

    def get_fallback(self, data):
        # Syntax: fallback <Comma separated list of probes>
        fallback = data[len("fallback") + 1:]
        record = {
            "fallback": fallback
        }

        return record


class ServiceScan():
    def __init__(self):
        self.allprobes = ServiceProbe().data
        self.thread_num = 5
        self.thread_pool = []
        self.service = {}
        # self.thread_lock = threading.Lock()


    def scan(self, host, port, protocol):
        # 按5组分
        # 同时开启5个线程进行扫描
        # 如果有一个线程命中指纹停止
        # 否则继续
        # 根据nmap probe进行扫描
        result = {}
        in_probes, ex_probes = self.filter_probes_by_port(port, self.allprobes)
        # 方法1: 使用线程来完成扫描
        scan = self.scan_in_thread
        # 方法2: 使用协程来完成扫描
        # scan = self.scan_in_async_wrapper
        # 任务开始
        in_probes_ret = scan(host,port,protocol,in_probes)
        if in_probes_ret:
            result = in_probes_ret
        else:
            ex_probes_ret = scan(host,port,protocol,ex_probes)
            if ex_probes_ret:
                result = ex_probes_ret
        self.service = {}
        return result

    def scan_in_async_wrapper(self,host,port,protocol,allprobes):
        asyncio.run(self.scan_in_async(host,port,protocol,allprobes))
        return self.service

    async def scan_in_async(self,host,port,protocol,allprobes):
        for i in range(0, len(allprobes), self.thread_num):
            for probe in allprobes[i:i + self.thread_num]:
                tasks = []
                t = asyncio.create_task(self.scan_with_probes_async(host,port,protocol,probe))
                tasks.append(t)
                for i in tasks:
                    await i
                if self.service:
                    # 如果遇到一条规则命中就退出
                    return self.service
        self.service = {}
        return self.service

    def scan_in_thread(self,host,port,protocol,allprobes):
        for i in range(0,len(allprobes), self.thread_num):
            for probe in allprobes[i:i + self.thread_num]:
                thread_handle = threading.Thread(target=self.scan_with_probes,args=(host,
                                                                                    port,
                                                                                    protocol,
                                                                                    probe,))
                self.thread_pool.append(thread_handle)
                thread_handle.start()
            for thread_handle in self.thread_pool:
                thread_handle.join()
                if self.service:
                    return self.service
        # 全部的probe都扫描没有返回unkown
        self.service = {}
        return self.service

    async def scan_with_probes_async(self, host, port, protocol, probes):
        """

        """
        nmap_fingerprint = {}
        record = await self.send_probestring_request_async(
            host, port, protocol, probes, SOCKET_TIMEOUT
        )
        if bool(record["match"]["versioninfo"]):
            nmap_fingerprint = record
            self.service = nmap_fingerprint
        return nmap_fingerprint

    def scan_with_probes(self, host, port, protocol, probes):
        """

        """
        nmap_fingerprint = {}
        record = self.send_probestring_request(
            host, port, protocol, probes, SOCKET_TIMEOUT
        )
        if bool(record["match"]["versioninfo"]):
            nmap_fingerprint = record
            self.service = nmap_fingerprint
        return nmap_fingerprint

    async def send_probestring_request_async(self, host, port, protocol, probe, timeout):
        """
        根据probe发送数据然后根据回报文的内容判断是否命中
        :param self:
        :param host:
        :param port:
        :param protocol:
        :param probe:
        :param timeout:
        :return:
        """
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)

        response = ""
        # 对协议类型进行扫描
        if (proto.upper() == protocol.upper()):

            if (protocol.upper() == "TCP"):
                response = await self.send_tcp_request_async(host, port, payload, timeout)
            elif (protocol.upper() == "UDP"):
                #  不进行udp扫描
                response = ""
                pass
            else:
                # 对其他类型的进行扫描
                response = ""
                pass
        try:
            nmap_pattern, nmap_fingerprint = self.match_probe_pattern(response, probe)

            record = {
                "probe": {
                    "probename": probe["probe"]["probename"],
                    "probestring": probe["probe"]["probestring"]
                },
                "match": {
                    "pattern": nmap_pattern,
                    "versioninfo": nmap_fingerprint
                }
            }
            return record
        except:
            pass


    def send_probestring_request(self, host, port, protocol, probe, timeout):
        """
        根据probe发送数据然后根据回报文的内容判断是否命中
        :param self:
        :param host:
        :param port:
        :param protocol:
        :param probe:
        :param timeout:
        :return:
        """
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)

        response = ""
        # 对协议类型进行扫描
        if (proto.upper() == protocol.upper()):

            if (protocol.upper() == "TCP"):
                response = self.send_tcp_request(host, port, payload, timeout)
            elif (protocol.upper() == "UDP"):
                #  不进行udp扫描
                response = ""
                pass
            else:
                # 对其他类型的进行扫描
                response = ""
                pass
        try:
            nmap_pattern, nmap_fingerprint = self.match_probe_pattern(response, probe)

            record = {
                "probe": {
                    "probename": probe["probe"]["probename"],
                    "probestring": probe["probe"]["probestring"]
                },
                "match": {
                    "pattern": nmap_pattern,
                    "versioninfo": nmap_fingerprint
                }
            }
            return record
        except:
            pass

    @asyncio.coroutine
    def send_tcp_request_async(self, host, port, payload, timeout):
        """
        发送数据包
        :param host: ip
        :param port: 端口
        :param payload: 数据
        :param timeout:超时
        :return:
        """
        data = b''
        try:
            # https://stackoverflow.com/questions/29756507/how-can-i-add-a-connection-timeout-with-asyncio
            connect = asyncio.open_connection(host,port)
            reader, writer = yield from asyncio.wait_for(connect, timeout=timeout)
            writer.write(payload)
            data = yield from asyncio.wait_for(reader.read(SOCKET_READ_BUFFERSIZE), timeout=timeout)
        except Exception as err:
            # TODO: 尝试做处理
            print(err)
            pass
        return data

    def send_tcp_request(self, host, port, payload, timeout):
        """
        发送数据包
        :param host: ip
        :param port: 端口
        :param payload: 数据
        :param timeout:超时
        :return:
        """
        data = b''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                client.settimeout(timeout)
                client.connect((host, int(port)))
                client.send(payload)
                while True:
                    _ = client.recv(SOCKET_READ_BUFFERSIZE) # TODO: recv连接超时
                    if not _: break
                    data += _
        except Exception as err:
            # TODO: 尝试做处理
            # print(err)
            pass
        return data

    def match_probe_pattern(self, data, probe):
        """
        根据 tcp 返回的数据包内容进行正则匹配
        :param data:
        :param probe:
        :return:
        """
        nmap_pattern, nmap_fingerprint = "", {}

        if not data:
            return nmap_pattern, nmap_fingerprint

        try:
            matches = probe['matches']
            for match in matches:
                pattern = match['pattern']
                # pattern_compiled = match['pattern_compiled']
                # print(pattern)
                pattern_compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                service = match['service']

                # https://github.com/nmap/nmap/blob/master/service_scan.cc#L476
                # regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                # data = str(data)
                # data = data.decode('utf-8')
                # data = data.decode()
                raw_data = codecs.unicode_escape_decode(data)[0]
                rfind = pattern_compiled.findall(raw_data)
                # rfind = pattern_compiled.search(data)

                if rfind and ("versioninfo" in match):
                    versioninfo = match['versioninfo']

                    rfind = rfind[0]
                    rfind = [rfind] if isinstance(rfind, str) else rfind

                    for index, value in enumerate(rfind):
                        dollar_name = "${}".format(index + 1)

                        versioninfo = versioninfo.replace(dollar_name, value)

                    nmap_pattern = pattern
                    nmap_fingerprint = self.match_versioninfo(versioninfo)
                    nmap_fingerprint.update({
                        "service": service
                    })

        except Exception as err:
            traceback.print_exc()
            raise err
        return nmap_pattern, nmap_fingerprint

    def match_versioninfo(self, versioninfo):
        """
        匹配版本信息
        :param versioninfo:
        :return:
        """
        record = {
            "vendorproductname": [],
            "version": [],
            "info": [],
            "hostname": [],
            "operatingsystem": [],
            "cpename": []
        }

        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname

        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version

        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info

        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname

        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem

        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype

        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename
        return record

    def filter_probes_by_port(self, port, probes):
        """

        :param port:
        :param probes:
        :return:
        """
        # {'match': {'pattern': '^LO_SERVER_VALIDATING_PIN\\n$',
        #            'service': 'impress-remote',
        #            'versioninfo': ' p/LibreOffice Impress remote/ '
        #                           'cpe:/a:libreoffice:libreoffice/'},
        #  'ports': {'ports': '1599'},
        #  'probe': {'probename': 'LibreOfficeImpressSCPair',
        #            'probestring': 'LO_SERVER_CLIENT_PAIR\\nNmap\\n0000\\n\\n',
        #            'protocol': 'TCP'},
        #  'rarity': {'rarity': '9'}}

        included = []
        excluded = []

        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if self.is_port_in_range(port, ports):
                    included.append(probe)
                else:  # exclude ports
                    excluded.append(probe)

            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if self.is_port_in_range(port, sslports):
                    included.append(probe)
                else:  # exclude sslports
                    excluded.append(probe)

            else:  # no [ports, sslports] settings
                excluded.append(probe)
        # 利用lamda排序,根据端口的稀有度来,稀有度高的可信度高,就提前扫描
        # included = sorted(included,reverse=True,key=lambda x:(x['rarity']['rarity']))
        # excluded = sorted(excluded,reverse=True,key=lambda x:(x['rarity']['rarity']))
        return included, excluded

    def is_port_in_range(self, port, nmap_port_rule):
        """Check port if is in nmap port range
        """
        bret = Falses

        ports = nmap_port_rule.split(',')  # split into serval string parts
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True

        return bret


import sys

print(sys.argv)
print(ServiceScan().scan(sys.argv[1],sys.argv[2],'tcp'))


