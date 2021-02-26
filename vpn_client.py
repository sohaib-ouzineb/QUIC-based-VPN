import argparse
import asyncio
import json
import logging
import pickle
import ssl
import base64
from typing import Optional, cast
from pytun import TunTapDevice

from dnslib.dns import QTYPE, DNSQuestion, DNSRecord

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicLogger
import fcntl
import struct
import os
import socket
import threading
import sys
import pytun
from pytun import TunTapDevice
COUNT=0

logger = logging.getLogger("client")

#initialize virtual interface tun
tun=TunTapDevice(name='mytunnel',flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
tun.addr='10.10.10.1'
tun.dstaddr='10.10.10.2'
tun.netmask='255.255.255.0'
tun.mtu=1048
tun.persist(True)
tun.up()
STREAM_ID=100
class VPNClient(QuicConnectionProtocol):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[None]] = None

    async def query(self) -> None:
	#client authentication using login/password, clear text because already encrypted by QUIC   	
        global STREAM_ID
        login=input("login: ")
        password=input("password: ")
        conc=login+":"+password
        conc=conc.encode('utf-8')
        auth=base64.b64encode(conc)
        query=auth
        #query = DNSRecord(q=DNSQuestion(dns_query, getattr(QTYPE, query_type)))
        stream_id = self._quic.get_next_available_stream_id()
        STREAM_id=stream_id
        end_stream = False
        self._quic.send_stream_data(stream_id, bytes(query), end_stream)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def tun_read(self) -> None:
        global tun,STREAM_ID
        while True:
            packet = tun.read(tun.mtu)
            #stream_id = self._quic.get_next_available_stream_id()
            #logger.debug(f"Stream ID: {stream_id}")
            end_stream = False
            self._quic.send_stream_data(STREAM_ID, bytes(packet), end_stream)
            waiter = self._loop.create_future()
            self._ack_waiter = waiter
            self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        global COUNT,tun
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                #answer = DNSRecord.parse(event.data)
                if(COUNT==0):
                        #authentication succeeded or failed 
                        COUNT=1
                        answer = event.data.decode("utf-8","ignore")      
                        waiter = self._loop.create_future()
                        self._ack_waiter = waiter
                        t=threading.Thread(target=self.tun_read)
                        t.start()
                else:
                        #decapsulate QUIC and write to internal tun
                        answer=event.data
                        tun.write(answer)
                        waiter = self._loop.create_future()
                        self._ack_waiter = waiter
                        


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def run(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    #query_type: str,
    #dns_query: str,
) -> None:
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=VPNClient,
    ) as client:
        client = cast(VPNClient, client)
        logger.debug("Sending connection query")
        await client.query()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VPN over QUIC client")
    parser.add_argument("-t", "--type", type=str, help="Type of record to ")
    parser.add_argument(
        "--host", type=str, help="The remote peer's host name or IP address"
    )
    parser.add_argument(
        "--port", type=int, default=784, help="The remote peer's port number"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    #parser.add_argument("--dns_type", help="The DNS query type to send")
    #parser.add_argument("--query", help="Domain to query")
    parser.add_argument(
        "-q", "--quic-log", type=str, help="log QUIC events to a file in QLOG format"
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(
        alpn_protocols=["dq"], is_client=True, max_datagram_frame_size=65536
    )
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicLogger()
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            logger.debug(f"Unable to read {args.session_ticket}")
            pass
    else:
        logger.debug("No session ticket defined...")

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run(
                configuration=configuration,
                host=args.host,
                port=args.port,
                #query_type=args.dns_type,
                #dns_query=args.query,
            )
        )
    finally:
        if configuration.quic_logger is not None:
            with open(args.quic_log, "w") as logger_fp:
                json.dump(configuration.quic_logger.to_dict(), logger_fp, indent=4)
