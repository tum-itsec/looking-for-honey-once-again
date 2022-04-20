#!/usr/bin/env python3

import asyncio

import sys
import select

import os
import json
import struct
import binascii
import argparse
import ipaddress
import csv

import ssl
import enum

from datetime import datetime
from RDP_structs import *
from RDP_consts import *

PACKET_NEGO = build_x224_conn_req()
PACKET_NEGO_CRED_SSP = build_x224_conn_req(protocols=PROTOCOL_SSL|PROTOCOL_HYBRID)
PACKET_NEGO_NOSSL = build_x224_conn_req(protocols=0) # Standard RDP security
PACKET_CONN = build_mcs_initial()
PACKET_CONN_RDPSEC = bytes.fromhex("0300019b02f0807f6582018f0401010401010101ff301a020122020102020100020101020100020101020300ffff0201023019020101020101020101020101020100020101020204200201023020020300ffff020300fc17020300ffff020101020100020101020300ffff02010204820129000500147c00018120000800100001c00044756361811201c0ea000c0008002003580201ca03aa00000000bb470000660066002d0075006e006900000000000000000000000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca0100000000001000070021040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000004c00c000d0000000000000002c00c00130000000000000006c00800000000000ac0080000000000")

class PeriodicBoundedSemaphore(asyncio.BoundedSemaphore):
    def __init__(self, conn_per_sec, loop):
        super().__init__(conn_per_sec)
        self.loop = loop
        self.refresh = loop.call_later(1, self._refresh)

    def _refresh(self):
        for _ in range(self._bound_value - self._value):
            self.release()
        self.refresh = self.loop.call_later(1, self._refresh)

class RDPProtocolException(Exception):
    pass

class SSLProtocol(asyncio.Protocol):
    def __init__(self, inner, loop, timeout):
        self.inner = inner
        self.timeout_time = timeout
        self.loop = loop
        self.inbuf_raw = b""
        self.inbuf_ssl = b""

    def _timeout(self):
        self.inner.timeout()
    
    def connection_made(self, transport):
        self.transport = transport
        self.timeout_handle = self.loop.call_later(self.timeout_time, self._timeout)

        self.ssl_in = ssl.MemoryBIO()
        self.ssl_out = ssl.MemoryBIO()
        self.ssl_enabled = False
        self.ssl_handshake_done = False
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
        self.ssl = ssl_ctx.wrap_bio(self.ssl_in, self.ssl_out)

        self.inner.connection_made(self)

    def start_tls(self):
        if self.ssl_enabled:
            raise Exception("TLS Handshake already performed or running!")
        self.try_ssl_handshake()
        self.ssl_enabled = True
    
    def try_ssl_handshake(self):
        try:
            self.ssl.do_handshake()
            self.ssl_handshake_done = True
            self.inner.tls_started()
        except ssl.SSLWantReadError:
            pass
        data = self.ssl_out.read()
        self.transport.write(data)

    def write(self, data):
        if self.ssl_enabled:
            self.ssl.write(data)
            enc_data = self.ssl_out.read()
            try:
                self.transport.write(enc_data)
            except ssl.SSLWantReadError:
                pass
        else:
            self.transport.write(data)

    def data_received(self, data):
        self.timeout_handle.cancel()
        self.timeout_handle = self.loop.call_later(self.timeout_time, self._timeout) # restart the timeout

        self.inbuf_raw += data
        if self.ssl_enabled:
            self.ssl_in.write(data)
            if self.ssl_handshake_done:
                try:
                    dec = self.ssl.read()
                    self.inbuf_ssl += dec
                    self.inner.data_received(dec)
                except ssl.SSLWantReadError:
                    pass
            else:
                self.try_ssl_handshake()
        else:
            self.inner.data_received(data)

    def close(self):
        self.transport.close()

    def connection_lost(self, exc):
        self.timeout_handle.cancel()
        self.inner.connection_lost(exc)
        
    def eof_received(self):
        self.inner.eof_received()

class RDPConnection(asyncio.Protocol):
    def __init__(self, on_con_close, loop, ip, conntype):
        self.on_con_close = on_con_close
        self.loop = loop
        self.state = 0
        self.data = {}
        self.error = None
        self.ssl_data = dict()
        self.eof = False
        self.is_timeout = False
        self.ip = ip
        self.conntype = conntype
        self.buffer = b""
        self.transport = None
    
    def timeout(self):
        self.is_timeout = True
        if self.transport is not None:
            self.transport.close()

    def connection_made(self, transport):
        self.transport = transport
        if self.conntype == PROTOCOL_HYBRID:
            transport.write(PACKET_NEGO_CRED_SSP)
        elif self.conntype == PROTOCOL_RDP:
            transport.write(PACKET_NEGO_NOSSL)
        else:
            transport.write(PACKET_NEGO)

    def tls_started(self):
        self.transport.write(PACKET_CONN)
        self.data["tls_cipher"] = self.transport.ssl.cipher()
        self.data["tls_certificate"] = self.transport.ssl.getpeercert(binary_form=True).hex()

    def data_received(self, data):
        self.buffer += data
        if len(self.buffer) > 4: # length information received?
            data_len = struct.unpack(">H", self.buffer[2:4])[0] # check header for length and compare with received length
            if len(self.buffer) >= data_len:
                self.buffer = self.buffer[data_len:] # TPKT done, receive next
                if self.state == 0:
                    self.state += 1
                    if self.conntype != PROTOCOL_RDP:
                        self.transport.start_tls()
                    else:
                        self.transport.write(PACKET_CONN_RDPSEC)
                else:
                    self.transport.close()

    def eof_received(self):
        self.eof = True
        
    def connection_lost(self, exc):
        print(f"{self.ip} {self.conntype}: ", end="")
        if exc is None:
            if self.eof:
                self.data["exception"] = 1
                print("Connection closed by remote host.")
            elif self.is_timeout:
                self.data["exception"] = 2
                print("Connection timed out.")
            else:
                print("Connection ended successfully.")
        elif isinstance(exc, ConnectionResetError):
            self.data["exception"] = 3
            print("Connection reset by remote host.")
        elif isinstance(exc, ssl.SSLError):
            self.data["exception"] = 5
            self.data["ssl_error_msg"] = repr(exc)
            print("SSLError occurred")
        else:
            self.data["exception"] = 4
            print(exc)
            print("Encountered unknown exception.")
        self.on_con_close.set_result(True)

async def handle_connection(loop, ip, timeout, sem, response_log, rdp_protocol):
    con_close = loop.create_future()
    on_tls = loop.create_future()
    await sem.acquire()
    try:
        transport, protocol = await asyncio.wait_for(loop.create_connection(lambda: SSLProtocol(RDPConnection(con_close, loop, ip, rdp_protocol), loop, timeout), ip, args.port), timeout=timeout)
    except asyncio.exceptions.TimeoutError:
        print(f"{ip} {rdp_protocol}: Connect timed out")
        return
    except ConnectionRefusedError as e:
        print(f"{ip} {rdp_protocol}: Connect refused")
        return
    except OSError as e:
        print(f"{ip} {rdp_protocol}: {e}")
        return
    await con_close
    fields = [
        protocol.inner.ip,
        protocol.inbuf_raw.hex(),
        protocol.inbuf_ssl.hex(),
        f"{rdp_protocol}",
        json.dumps(protocol.inner.data)
    ]
    response_log.writerow(fields)
    return

async def main(args):
    loop = asyncio.get_running_loop()
    sem = PeriodicBoundedSemaphore(args.max_cps, loop)
    stdin_closed = False

    ips_buffered = []
    connections = set()
    finished = 0
    with open(os.path.join(results_dir, "response_dump.csv"), "a") as response_log_f:
        response_log = csv.writer(response_log_f)
        while True:
            if finished % args.progress == 0:
                sys.stderr.write("Finished: {}\r".format(finished))
            
            while len(connections) < args.max_connections: # create as many concurrent connections as possible
                ready = select.select([sys.stdin], [], [], 0.0)[0]
                if not ready: # no input available on stdin
                    if not connections: # nothing to do, only waiting for input
                        ready = select.select([sys.stdin], [], [])[0]
                    else: # no input in time
                        break

                ip = ready[0].readline().strip()
                if not ip: # stdin is closed
                    if not connections:
                        return # stdin is closed, no connections remaining, we are done
                    else:
                        break # stdin is closed, wait for remaining connections

                try:
                    check = ipaddress.ip_address(ip)
                    if check.is_global or not args.global_check: # add a check for any subnet here
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_SSL))) # Standard packet
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_HYBRID))) # CredSSP enabled
                        connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, response_log, PROTOCOL_RDP))) # RPD Standard Security without TLS
                except ValueError:
                    pass


            _, connections = await asyncio.wait(connections, return_when=asyncio.FIRST_COMPLETED) # wait for first connection to finish
            finished += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-connections", type=int, dest="max_connections", default=1000)
    parser.add_argument("--timeout", type=float, dest="timeout", default=10)
    parser.add_argument("--port", dest="port", default=3389)
    parser.add_argument("--max-cps", type=int, dest="max_cps", default=100)
    parser.add_argument("--progress", type=int, dest="progress", default=500)
    parser.add_argument("--output", type=str)
    parser.add_argument("--no-global-check", action="store_false", dest="global_check", default=True)
    args = parser.parse_args()
    
    start = datetime.now()
    now = start.strftime("%y_%m_%d_%H_%M_%S")
    if args.output:
        results_dir = os.path.join(args.output, "scans_" + now)
    else:
        results_dir = "scans_" + now

    try:
        import git
        repo = git.Repo(os.getcwd())
        head = str(repo.commit("HEAD"))[:7]
        clean = "clean" if not (repo.index.diff(None) or repo.untracked_files) else "dirty"
        results_dir += "_{}_{}".format(head, clean)
        print("# {} commit {} {}".format(now, head, clean))
    except ImportError:
        print("# {} (git status unknown)".format(now))
        pass

    os.mkdir(results_dir)
    keylogpath = os.path.join(results_dir, "sslkeys.log")
    os.environ["SSLKEYLOGFILE"] = keylogpath
    
    asyncio.run(main(args))

    end = datetime.now()
    print("Elapsed time: {}".format(str(end - start)))
