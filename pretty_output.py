from prettytable import PrettyTable
from scapy.packet import Packet
import os


class Prettifier:
    def __init__(self, request_count: int):
        self._row_index = 1
        self._request_count = request_count
        self._table = PrettyTable(['#', 'Replies'] + [f'Request #{index}' for index in range(request_count)] + ['ASN'])

    def update(self, replies: list[Packet], elapsed: list[float], asn: str = None):
        _replies = set([reply.src for reply in replies]) if replies else '*'
        _elapsed = [f'{round(time, 4)} ms' for time in elapsed] if elapsed else ['*' for _ in range(self._request_count)]
        _asn = [asn] if asn else ['-']

        self._table.add_row([f'{self._row_index}'] + list(_replies) + _elapsed + _asn)

        Prettifier.__clear()
        print(self._table)

        self._row_index += 1

    @staticmethod
    def __clear():
        os.system('cls')
