import sys
from dataclasses import dataclass
import socket
from functools import wraps
import time
import json
import click
import ipwhois
from scapy import packet
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import sr1
from scapy.supersocket import L3RawSocket


@dataclass
class Protocols:
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"

    @staticmethod
    def get_port_by_name(protocol: str) -> int:
        with open('protocols.json', 'r') as f:
            protocols = json.load(f)
            port = protocols[protocol.lower()]["port"]
        if port is None:
            raise ValueError(f"Unknown protocol {protocol}")
        return port

    @staticmethod
    def parse_protocol(protocol: str) -> str:
        if protocol.lower() in Protocols.__dict__:
            return protocol.lower()
        else:
            raise ValueError(f"Unknown protocol {protocol}")


def timeit(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        return result, total_time

    return timeit_wrapper


class Tracerouter:
    def __init__(self, destination: str, str_protocol: str,
                 port: int = -1, timeout: int = 2,
                 max_ttl: int = 25, verbose: bool = False):
        self.__destination = destination
        self.__protocol = Protocols.parse_protocol(str_protocol)
        self.__timeout = timeout
        self.__max_ttl = max_ttl
        self.__verbose = verbose
        self.__max_attempt = 3
        if port == -1:
            self.__port = Protocols.get_port_by_name(self.__protocol)

        conf.L3socket = L3RawSocket

    def __get_request(self, ttl: int) -> packet:
        if self.__is_ipv6(self.__destination):
            ip = IPv6(dst=self.__destination, hlim=ttl)
        else:
            ip = IP(dst=self.__destination, ttl=ttl)
        if self.__protocol == Protocols.TCP:
            return ip / TCP(dport=self.__port)
        if self.__protocol == Protocols.UDP:
            return ip / UDP(dport=self.__port)
        if self.__protocol == Protocols.ICMP:
            if self.__is_ipv6(self.__destination):
                return ip / ICMPv6EchoRequest()
            else:
                return ip / ICMP()

        raise ValueError(f"Unknown protocol {self.__protocol}")

    @timeit
    def __senf_receive_one_packet(self, request: packet) -> tuple:
        return sr1(request, timeout=self.__timeout, verbose=False)

    def run(self):
        number = 1
        for ttl in range(1, self.__max_ttl + 1):
            request = self.__get_request(ttl)
            response, delay = None, 0
            for attempt in range(self.__max_attempt):
                response, delay = sr1(request, timeout=self.__timeout, verbose=False)
                if response is not None:
                    break
            if not response:
                print(f'{number} *')
            else:
                interval = round(delay * 1000, 2)
                output = f'{number} {response.src} {interval} ms'
                if self.__verbose:
                    ip_domain = self.__get_autonomous_system(response.src)
                    output += f' ({ip_domain})'
                print(output)
                if self.__destination == response.src:
                    break
            number += 1

    @staticmethod
    def __get_autonomous_system(ip: str) -> str | None:
        try:
            res = ipwhois.IPWhois(ip).lookup_rdap(depth=1)['asn']
            if res is None:
                res = 'NA'
            return res
        except ipwhois.exceptions.IPDefinedError:
            return 'NA'

    @staticmethod
    def __is_ipv6(ip: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


@click.command()
@click.option('--timeout', '-t', default=2, help='Timeout')
@click.option('--port', '-p', default=-1, help='Port')
@click.option('--max_ttl', '-n', default=25, help='Max TTL')
@click.option('--verbose', '-v', is_flag=True,
              default=False, help='Verbose mode')
@click.argument('ip', nargs=1)
@click.argument('protocol', nargs=-1)
def main(timeout: int, port: int,
         max_ttl: int, verbose: bool,
         ip: str, protocol: str):
    tracerouter = Tracerouter(ip, protocol[0], port,
                              timeout, max_ttl, verbose)
    tracerouter.run()


if __name__ == 'main':
    main(sys.argv[1:])
