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

from datetime import datetime
from SMB_structs import smb_setupandx_request, smb2_setup_request, unpack_response, unpack_ntlm

PACKETS_DISTINCTIVE = [binascii.unhexlify(el) for el in ["00000035ff534d4272ab0000001843c80001f0debc9a7856341200000000000000000000001200024572726f720002534d4220322e30303200", "0000009cff534d4273ab0000001843c8000000000000000000000000efbe0000000000000cfffa0000ffff02000100afbaedda4a00edceaffa54c000806100604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d53535000010000001582086200000000280000000000000028000000060100000000000f0055006e00690078000000530061006d00620061000000"]]
PACKETS_SMBv1 = [binascii.unhexlify("0000002fff534d4272000000001841c80000000000000000000000000000000000000100000c00024e54204c4d20302e313200")]
PACKETS_SMB1_NEGO = binascii.unhexlify("000000d4ff534d4272000000001841c8000000000000000000000000000000000000010000b100024e54204c414e4d414e20312e3000024e54204c4d20302e31320002534d4220322e3f3f3f00025043204e4554574f524b2050524f4752414d20312e3000024d4943524f534f4654204e4554574f524b5320312e303300024d4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e312e3000024c4d312e32583030320002444f53204c414e4d414e322e3100024c414e4d414e322e31000253616d62610002534d4220322e30303200")
PACKETS_SMB2_NEGO = binascii.unhexlify("000000b6fe534d4240000100000000000000010000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000024000800010000000000000094a99c9e5c186c4cab61eca2a7ebe238780000000200000002021002220224020003020310031103000000000100260000000000010020000100b7b343261a7e2129bf9c7fcf41fb3f2ef05e21381ae4cf4029f1ee9c1a938c0000000200060000000000020001000200")
PACKETS_SMB1_SETUP = binascii.unhexlify("0000009cff534d4273000000001841c800000000000000000000000000000000000002000cff000000ffff02000100000000004a000000000054c000806100604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d53535000010000000582886200000000280000000000000028000000060100000000000f0055006e00690078000000530061006d00620061000000")
PACKETS_SMB2_SETUP = binascii.unhexlify("000000a2fe534d4240000100000000000100010000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000019000001000000000000000058004a000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d535350000100000005a280e200000000000000000000000028000000060072170000000f")

class PeriodicBoundedSemaphore(asyncio.BoundedSemaphore):
    def __init__(self, conn_per_sec, loop):
        super().__init__(conn_per_sec)
        self.loop = loop
        self.refresh = loop.call_later(1, self._refresh)

    def _refresh(self):
        for _ in range(self._bound_value - self._value):
            self.release()
        self.refresh = self.loop.call_later(1, self._refresh)

class SMBConnection(asyncio.Protocol):
    def __init__(self, on_con_close, loop, ip, timeout, login, smbv1support):
        self.on_con_close = on_con_close
        self.loop = loop
        self.state = 0
        self.data = []
        self.ip = ip
        self.eof = False
        self.error = None
        self.bytes_to_receive = 0
        self.timeout_time = timeout
        self.is_timeout = False
        self.timeout_handle = loop.call_later(timeout, self._timeout)
        self.login = login
        self.v1conn = False
        self.smbv1support = smbv1support

    def write_data(self):
        with open(os.path.join(results_dir, "response_dump.csv"), "a") as f:
            f.write("{}, {}, {}, {}\n".format(self.ip, self.login, self.smbv1support, json.dumps(self.data)))

    def connection_made(self, transport):
        if self.login:
            transport.write(PACKETS_SMB1_NEGO)
        elif self.smbv1support:
            transport.write(PACKETS_SMBv1[0])
        else:
            transport.write(PACKETS_DISTINCTIVE[0])
        self.transport = transport

    def data_received(self, data):
        self.timeout_handle.cancel()
        self.timeout_handle = self.loop.call_later(self.timeout_time, self._timeout) # restart the timeout

        if self.bytes_to_receive > 0: # more data for this state is expected
            self.data[-1]["data"] += binascii.hexlify(data).decode("ascii")
            self.bytes_to_receive -= len(data)
        else:
            self.data.append({"data": binascii.hexlify(data).decode("ascii"), "exception": -1})
            if len(data) < 4:
                self.error = "Short Length field"
                self.transport.close()
                return
            data_len = struct.unpack(">i", data[:4])[0] # check header for length and compare with received length
            if data_len + 4 > len(data):
                self.bytes_to_receive = data_len + 4 - len(data)

            if self.login:
                if self.state == 0:
                    try:
                        if data[4] == 0xff:
                            self.v1conn = True
                            self.transport.write(PACKETS_SMB1_SETUP)
                        elif data[4] == 0xfe:
                            self.transport.write(PACKETS_SMB2_NEGO)
                        else:
                            self.error = "Invalid Version string: {}".format(str(data[4]))
                            self.transport.close()
                    except IndexError as e:
                        self.error = str(e)
                        self.transport.close()
                elif self.state == 1:
                    if self.v1conn:
                        try:
                            chall_msg_data = unpack_response(data)
                            chall_msg_gssapi = chall_msg_data[1][2][7]
                            uid = chall_msg_data[1][1][11]
                            server_info, server_chall = unpack_ntlm(chall_msg_gssapi)
                            self.transport.write(smb_setupandx_request["auth_pack"](server_info, server_chall, uid=uid))
                        except Exception as e:
                            self.error = str(e)
                            self.transport.close()
                    else:
                        self.transport.write(PACKETS_SMB2_SETUP)
                elif self.state == 2:
                    if self.v1conn:
                        self.transport.close()
                    else:
                        try:
                            chall_msg_data = unpack_response(data)
                            chall_msg_gssapi = chall_msg_data[1][2][-1]
                            session_id = chall_msg_data[1][1][12]
                            server_info, server_chall = unpack_ntlm(chall_msg_gssapi)
                            self.transport.write(smb2_setup_request["auth_pack"](server_info, server_chall, session_id))
                        except Exception as e:
                            self.error = str(e)
                            self.transport.close()
                else:
                    self.transport.close() # only response to first packet was important
                self.state += 1
            elif self.smbv1support:
                self.transport.close()
            else:
                self.state += 1
                if self.state == len(PACKETS_DISTINCTIVE):
                    self.transport.close() # regular session close
                else:
                    self.transport.write(PACKETS_DISTINCTIVE[self.state])
        
    def connection_lost(self, exc):
        self.timeout_handle.cancel()
        self.on_con_close.set_result(True)
        print("{}{}{}: ".format(self.ip, " (Login)" if self.login else "", " (SMBv1)" if self.smbv1support else ""), end="")
        if exc is None:
            if self.eof:
                self.data.append({"data": "", "exception": 0})
                print("Connection closed by remote host.")
            elif self.is_timeout:
                self.data.append({"data": "", "exception": 1})
                print("Connection timed out.")
            elif self.error:
                self.data.append({"data": "", "exception": 3})
                print("Unexpected Behavior.")
            else:
                self.transport.close()
                print("Connection ended successfully.")
        elif isinstance(exc, ConnectionResetError):
            self.data.append({"data": "", "exception": 2})
            print("Connection reset by remote host.")
        elif isinstance(exc, Exception):
            self.data.append({"data": "", "exception": 4})
            print("Encountered unknown exception.")
        self.write_data()

    def eof_received(self):
        self.eof = True

    def _timeout(self):
        self.is_timeout = True
        self.transport.close()
        
async def handle_connection(loop, ip, timeout, sem, login, smbv1support):
    con_close = loop.create_future()
    await sem.acquire()
    try:
        _, protocol = await asyncio.wait_for(loop.create_connection(lambda: SMBConnection(con_close, loop, ip, timeout, login, smbv1support), ip, args.port), timeout=timeout)
    except:
        print("{}{}: Connection failed.".format(ip, " (Login)" if login else ""))
        return
    await con_close
    return protocol

async def main(args):
    loop = asyncio.get_running_loop()
    sem = PeriodicBoundedSemaphore(args.max_cps, loop)
    stdin_closed = False

    connections = set()
    ips_buffered = []
    finished = 0
    while True:
        if finished % args.progress == 0:
            sys.stderr.write("Finished: {}\r".format(finished))
        
        while True: # buffer everything available from stdin
            if stdin_closed:
                if (not connections) and (not ips_buffered):
                    return # finished
                break

            ready = select.select([sys.stdin], [], [], 0.0)[0]
            if not ready: # no input available on stdin
                if (not connections) and (not ips_buffered): # nothing to do, only waiting for input
                    ready = select.select([sys.stdin], [], [])[0]
                else: # no input in time
                    break

            ip = ready[0].readline().strip()
            if not ip: # stdin is closed
                stdin_closed = True
                if (not connections) and (not ips_buffered):
                    return # stdin is closed, no connections remaining, we are done
                else:
                    continue # stdin is closed, wait for remaining connections
            else:
                ips_buffered.append(ip)

        while len(connections) < args.max_connections: # create as many concurrent connections as possible
            if ips_buffered:
                ip = ips_buffered[0]
                del ips_buffered[0]
            else: # no connection available at the moment, wait for more
                break

            try:
                check = ipaddress.ip_address(ip)
                if check.is_global and args.global_check: # add a check for any subnet here
                    connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, False, True))) # SMBv1 Support Scan
                    connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, True, False))) # Guest Login Scan
                    connections.add(asyncio.create_task(handle_connection(loop, ip, args.timeout, sem, False, False))) # Regular Differentiation Scan
            except ValueError:
                pass

        _, connections = await asyncio.wait(connections, return_when=asyncio.FIRST_COMPLETED) # wait for first connection to finish
        finished += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-connections", type=int, dest="max_connections", default=1000)
    parser.add_argument("--timeout", type=float, dest="timeout", default=10)
    parser.add_argument("--port", dest="port", default=445)
    parser.add_argument("--max-cps", type=int, dest="max_cps", default=100)
    parser.add_argument("--progress", type=int, dest="progress", default=500)
    parser.add_argument("--no-global-check", action="store_false", dest="global_check", default=True)
    parser.add_argument("--output", type=str)
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
    
    asyncio.run(main(args))

    end = datetime.now()
    print("Elapsed time: {}".format(str(end - start)))
