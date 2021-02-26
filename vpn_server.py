#based on the aioquic library that can be found at https ://github.com/aiortc/aioquic
import argparse
import asyncio
import json
import logging
import base64
from typing import Dict, Optional



from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicLogger
from aioquic.tls import SessionTicket
import fcntl
import struct
import os
import socket
import threading
import sys
import pytun
from pytun import TunTapDevice

try:
    import uvloop
except ImportError:
    uvloop = None
    
COUNT = 0
tun = TunTapDevice(name='mytun_serv',flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
tun.addr = '10.10.10.2'
tun.dstaddr='10.10.10.1'
tun.netmask = '255.255.255.0'
tun.mtu=1048
tun.persist(True)
tun.up()               	
STREAM_ID=100
class VPNServerProtocol(QuicConnectionProtocol):

    # -00 specifies 'dq', 'doq', and 'doq-h00' (the latter obviously tying to
    # the version of the draft it matches). This is confusing, so we'll just
    # support them all, until future drafts define conflicting behaviour.
    SUPPORTED_ALPNS = ["dq", "doq", "doq-h00"]
    

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vpn = None

    def tun_read(self):
        global tun,STREAM_ID
        while True:
            #intercept packets that are about to be sent
            packet=tun.read(tun.mtu)
            #stream_id = self._quic.get_next_available_stream_id()
            end_stream = False
            #send them through the appropriate QUIC Stream
            self._quic.send_stream_data(STREAM_ID, bytes(packet), end_stream)
            self.transmit()

    def quic_event_received(self, event):
        global COUNT,tun, STREAM_ID
        if isinstance(event, StreamDataReceived):

            if(COUNT==0):
                #authentication check
                data = self.auth_check(event.data)
                end_stream = False
                STREAM_ID = event.stream_id
                self._quic.send_stream_data(event.stream_id, data, end_stream)
                self.transmit()
                
                #if auth successful, start reading on local tun interface and 
                #prepare to receive QUIC|IP|QUIC
                if(data==bytes("Authentication_succeeded","utf-8")):
                    t=threading.Thread(target=self.tun_read)
                    t.start()
                    COUNT=1
            else:
                 #QUIC event received => decapsulate and write to local tun
                 answer=event.data
                 tun.write(bytes(answer))

    def auth_check(self,payload) :
        decoded_auth = base64.b64decode(payload).decode("utf-8", "ignore")	
        login=decoded_auth.partition(":")[0]
        password=decoded_auth.partition(":")[2]
        print("login = ",login)
        print("password = ",password)
        bool= (login=="root" and password=="toor")
        if(bool):
            return bytes("Authentication_succeeded","utf-8")
        else:
            return bytes("Authentication_failed","utf-8")


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) :
        self.tickets = {}

    def add(self, ticket) :
        self.tickets[ticket.ticket] = ticket

    def pop(self, label) :
        return self.tickets.pop(label, None)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="VPN over QUIC server")
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=784,
        help="listen on the specified port (defaults to 784)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        required=True,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    #parser.add_argument(
    #    "-r",
    #    "--resolver",
    #    type=str,
    #    default="8.8.8.8",
    #    help="Upstream Classic DNS resolver to use",
    #)
    #parser.add_argument(
    #    "-s",
    #    "--stateless-retry",
    #    action="store_true",
    #    help="send a stateless retry for new connections",
    #)
    parser.add_argument(
        "-q", "--quic-log", type=str, help="log QUIC events to a file in QLOG format"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.quic_log:
        quic_logger = QuicLogger()
    else:
        quic_logger = None

    configuration = QuicConfiguration(
        alpn_protocols=["dq"],
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=quic_logger,
    )

    configuration.load_cert_chain(args.certificate, args.private_key)

    ticket_store = SessionTicketStore()

    if uvloop is not None:
        uvloop.install()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        serve(
            args.host,
            args.port,
            configuration=configuration,
            create_protocol=VPNServerProtocol,
            session_ticket_fetcher=ticket_store.pop,
            session_ticket_handler=ticket_store.add,
            #stateless_retry=args.stateless_retry,
        )
    )
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if configuration.quic_logger is not None:
            with open(args.quic_log, "w") as logger_fp:
                json.dump(configuration.quic_logger.to_dict(), logger_fp, indent=4)
