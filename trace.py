import argparse

from pretty_output import Prettifier
from scapy.packet import Packet
from ipwhois import IPWhois, IPDefinedError

from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1


class Trace:
    def __init__(self, host: str, queries: int, timeout: int, ipv6: bool, verbose: bool):
        self._host = host
        self._queries = queries
        self._timeout = timeout
        self._ipv6 = ipv6
        self._verbose = verbose
        self._output = Prettifier(self._queries)

    def __send(self, request_packet: Packet) -> list[Packet]:
        answers = []

        for _ in range(self._queries):
            reply = sr1(request_packet, verbose=0, timeout=self._timeout)

            if reply is not None:
                reply.reply_time = reply.time - request_packet.sent_time
                answers.append(reply)

        return answers

    def __get_request_packet(self, ttl: int) -> Packet:
        if self._ipv6:
            return IPv6(dst=self._host, hlim=ttl) / ICMPv6EchoRequest()

        return IP(dst=self._host, ttl=ttl) / ICMP()

    @staticmethod
    def __get_asn(replies: list[Packet]) -> str:
        try:
            return ' '.join(IPWhois(ip).ipasn.lookup()['asn'] for ip in set(reply.src for reply in replies))
        except IPDefinedError:
            return 'Private'

    def traceroute(self):
        packet_index = 1
        replies = []
        terminating_type = 3 if self._ipv6 else 11

        while not replies or replies[0].type == terminating_type:
            request_packet = self.__get_request_packet(packet_index)
            replies = self.__send(request_packet)

            if not replies:
                self._output.update([], [], "*" if self._verbose else None)
                packet_index += 1
                continue

            self._output.update(
                replies,
                [reply.reply_time for reply in replies],
                Trace.__get_asn(replies) if self._verbose else None)

            if replies[0].type != (3 if self._ipv6 else 11):
                break

            packet_index += 1


parser = argparse.ArgumentParser()

parser.add_argument('ip_address', type=str)
parser.add_argument('-t', '--timeout', type=float, default=2)
parser.add_argument('-n', type=int, default=3)
parser.add_argument('-v', '--verbose', action='store_true')
parser.add_argument('-6', action='store_true', dest='ipv6')

args = parser.parse_args()

trace = Trace(args.ip_address, args.n, args.timeout, args.ipv6, args.verbose)
trace.traceroute()
