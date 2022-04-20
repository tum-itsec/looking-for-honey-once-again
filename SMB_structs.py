import sys
import hmac
import random
import struct
import hashlib
import binascii
from datetime import datetime, timedelta

def MD4(): return hashlib.new('md4')

def ms_time_to_unix(time):
    if time == 0:
        return 0
    return datetime(1601,1,1) + timedelta(microseconds=(time / 10))

def generic_unpack(format, len, data):
    return struct.unpack(format, data[:len]), len

def generic_extension_unpack(format, len_format, len_orig, len_start, len_end, data, len_offset=0):
    len = int(struct.unpack(len_format, data[len_start:len_end])[0]) + len_offset
    format += str(len) + "s"
    return struct.unpack(format, data[:(len_orig + len)]), (len_orig + len)

def resolve_dialect(dialect):
    dct = {
        "0x2ff": "SMB 2 any",
        "0x202": "SMB 2.02",
        "0x210": "SMB 2.1",
        "0x222": "SMB 2.2.2",
        "0x224": "SMB 2.2.4",
        "0x300": "SMB 3.0",
        "0x302": "SMB 3.0.2",
        "0x311": "SMB 3.1.1",
        "0xffff": "Dialect Negotiation Fail"
    }
    try:
        return "{} ({})".format(hex(dialect), dct[hex(dialect)])
    except KeyError:
        return "{} (Unknown/Invalid Dialect)".format(hex(dialect))

def deinterlace_zeroes(data):
    return str(data.replace(b"\x00",b""))

def interlace_zeroes(data):
    return b"".join([bytes([c]) + b"\x00" for c in data])

def unpack_ntlm(data):
    chall_msg_ntlm = data[data.find(b"NTLMSSP"):]
    ntlmssp_header = struct.unpack("<8sIHHIIQQHHIQ", chall_msg_ntlm[:56])
    server_info = chall_msg_ntlm[ntlmssp_header[10]:ntlmssp_header[10] + ntlmssp_header[8]]
    server_chall = struct.pack("<Q", ntlmssp_header[6])
    
    return server_info, server_chall

def parse_gssapi(data):
    offset = 0x1f
    if not data[offset:offset + 7] == b"NTLMSSP":
        offset = data.find(b"NTLMSSP")
    if offset == -1:
        return data

    message_types = {
        "1": "NEGOTIATE_MESSAGE",
        "2": "CHALLENGE_MESSAGE",
        "3": "AUTHENTICATE_MESSAGE"
    }

    ntlmssp_data = data[offset:]
    message_type = struct.unpack("<I", ntlmssp_data[8:12])[0]
    
    if message_type == 1:
        ntlmssp_header = struct.unpack("<8sIIHHIHHIQ", ntlmssp_data[:40])

        dnf_len = ntlmssp_header[3]
        wf_len = ntlmssp_header[6]
        dnf_field = struct.unpack("<" + str(dnf_len) + "s", ntlmssp_data[40:40 + dnf_len])
        wf_field = struct.unpack("<" + str(wf_len) + "s", ntlmssp_data[40 + dnf_len:40 + dnf_len + wf_len])

        ret = [
            ("NTLM Message Type", str(ntlmssp_header[1]) + " ({})".format(message_types[str(ntlmssp_header[1])])),
            ("Negotiate Flags", hex(ntlmssp_header[3])),
            ("Version", hex(ntlmssp_header[9])),
            ("Domain Name", dnf_field),
            ("Workstation Name", wf_field)
        ]
    elif message_type == 2:
        ntlmssp_header = struct.unpack("<8sIHHIIQQHHIQ", ntlmssp_data[:56])

        tnf_len = ntlmssp_header[2]
        tnf_off = ntlmssp_header[4]
        tif_len = ntlmssp_header[8]
        tif_off = ntlmssp_header[10]
        tnf_field = struct.unpack("<" + str(tnf_len) + "s", ntlmssp_data[tnf_off:tnf_off + tnf_len])[0]
        tif_data = ntlmssp_data[tif_off:tif_off + tif_len]

        tif_fields = []
        i = 0
        while i < len(tif_data):
            field_type = struct.unpack("<H", tif_data[i:i + 2])[0]
            i += 2
            field_len = struct.unpack("<H", tif_data[i:i + 2])[0]
            i += 2
            field_name = struct.unpack("<" + str(field_len) + "s", tif_data[i:i + field_len])[0]
            i += field_len
            tif_fields.append((field_type, field_len, field_name))

        info_types = {
            "1": "NetBios Computer Name",
            "2": "NetBios Domain Name",
            "3": "DNS Computer Name",
            "4": "DNS Domain Name",
            "5": "DNS Tree Name",
            "6": "Flags",
            "7": "Timestamp",
            "8": "SingleHost",
            "9": "Target Server SPN",
            "10": "Channel Bindings"
        }

        ret = [
            ("NTLM Message Type", str(ntlmssp_header[1]) + " ({})".format(message_types[str(ntlmssp_header[1])])),
            ("NTLM Server Challenge", hex(ntlmssp_header[6])),
            ("Reserved", ntlmssp_header[7]),
            ("Version", hex(ntlmssp_header[11])),
            ("Target Name", deinterlace_zeroes(tnf_field)),
            ("Target Info", "")
        ]

        for el in tif_fields:
            if el[0] == 6:
                ret.append(("\t " + info_types[str(el[0])], hex(struct.unpack("<I", el[2])[0])))
            elif el[0] == 7:
                ret.append(("\t " + info_types[str(el[0])], ms_time_to_unix(struct.unpack("<Q", el[2])[0])))
            elif el[0] != 0:
                ret.append(("\t " + info_types[str(el[0])], deinterlace_zeroes(el[2])))
    elif message_type == 3:
        ntlmssp_header = struct.unpack("<8sIHHIHHIHHIHHIHHIHHIIQ16s", ntlmssp_data[:88])

        ret = [
            ("NTLM Message Type", str(ntlmssp_header[1]) + " ({})".format(message_types[str(ntlmssp_header[1])])),
            ("Negotiate Flags", hex(ntlmssp_header[20])),
            ("Version", hex(ntlmssp_header[21])),
            ("MIC", ntlmssp_header[22])
        ]
    else:
        ret = []

    return ret

error_codes = {
    "Connection Closed": "0",
    "<class 'socket.timeout'>": "1",
    "<class 'ConnectionResetError'>": "2",
    "<class 'BrokenPipeError'>": "3"
}

error_codes_inv = {
    "0": "Connection Closed",
    "1": "Socket Timeout",
    "2": "Connection Reset",
    "3": "Unexpected Behavior",
    "4": "Unkown Error",
    "5": "Invalid Format"
}

def print_flags(flag, field_len, data, rev_labels=False):
    bin_str = bin(data)[2:].rjust(field_len, "0")
    labels = flag_labels[flag][0] if not rev_labels else list(reversed(flag_labels[flag][0]))
    indices = flag_labels[flag][1]
    ret = [bin_str]
    for i, j in enumerate(indices):
        try:
            ret.append((labels[i],  bool(int(bin_str[j]))))
        except IndexError:
            ret.append(("?", bool(int(bin_str[j]))))
    return ret
    
flag_labels = {
    "SMB Header 1": (["Response", "Notify", "OpLocks", "Canonicalized Pathnames", "Case Sensitivity", "Receive Buffer Posted", "Lock and Read"], [0, 1, 2, 3, 4, 6, 7]),
    "SMB Header 2": (["Unicode Strings", "NT Error Codes", "Execute-only Reads", "Dfs", "Extended Security Negotiation", "Reparse Path", "Long Names Used", "Security Signatures Required", "Compression requested", "Security Signatures supported", "Extended Attributes supported", "Long Names allowed"], [0, 1, 2, 3, 4, 5, 9, 11, 12, 13, 14, 15]),
    "SMB Negotiate Capabilities": (["Raw Mode", "MPX Mode", "Unicode", "Large Files", "NT SMBs", "RPC Remote APIs", "NT Status Codes", "Level 2 Oplocks", "Lock and Read", "NT Find", "Dfs", "Infolevel Passthru", "Large ReadX", "Large WriteX", "LWIO", "UNIX extensions", "Compressed Data", "Dynamic Reauth", "Extended Security"], [0, 2, 6, 8, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
    "SMB2 Header": (["Response", "Async Command", "Chained", "Signed", "Priority", "DFS operation", "Replay operation"], [2, 3, 27, 28, 29, 30, 31]),
    "SMB2 Negotiate Capabilities": (["DFS", "Leasing", "Large MTU", "Multi Channel", "Persistent Handles", "Directory Leasing", "Encryption"], [25, 26, 27, 28, 29, 30, 31]),
    "SMB2 Session Setup Request": (["Session Binding Request"], [7]),
    "SMB2 Session Setup Response": (["Encrypt", "Null", "Guest"], [29, 30, 31]),
}

net_bios_header = {
    "name": "net_bios_header",
    "format": ">I",
    "labels": ["Length"],
    "types": [int],
    "len": 4,
    "unpack": lambda x: generic_unpack(">I", 4, x)
}

smb_header = {
    "name": "smb_header",
    "format": "<c3sBIBHHQHHHHH",
    "labels": ["SMB Version", "Server Component", "SMB Command", "NT Status", "Flags 1", "Flags 2", "Process ID", "Signature", "Reserved", "Tree ID", "Process ID", "User ID", "Multiplex ID"],
    "types": [str, str, hex, hex, lambda x: print_flags("SMB Header 1", 8, x), lambda x: print_flags("SMB Header 2", 16, x), int, int, int, hex, int, int, int],
    "len": 32,
    "unpack": lambda x: generic_unpack("<c3sBIBHHQHHHHH", 32, x)
}

smb2_header = {
    "name": "smb2_header",
    "format": "<c3sHHIHHIIQIIQ16s",
    "labels": ["SMB Version", "Server Component", "Header Lenght", "Credit Charge", "NT Status", "Command", "Credits granted", "Flags", "Chain offset", "Message ID", "Process ID/Reserved", "Tree ID", "Session ID", "Signature"],
    "types": [str, str, int, int, hex, hex, int, lambda x: print_flags("SMB2 Header", 32, x, rev_labels=True), int, int, int, int, int, str],
    "len": 64,
    "unpack": lambda x: generic_unpack("<c3sHHIHHIIQIIQ16s", 64, x)
}

def smb_negotiate_request_pack(dialects, smbver=b'\xff', smbstr=b'SMB', smbcmd=0x72, ntstatus=0, flags1=0x18, flags2=0xc841, pidhigh=0, sig=0, reser1=0, tid=0, pidlow=0, uid=0, mid=1, dialpad=b"\x02", lennb=True, lenwc=True):
    smb_header_packed = struct.pack(smb_header["format"], smbver, smbstr, smbcmd, ntstatus, flags1, flags2, pidhigh, sig, reser1, tid, pidlow, uid, mid)
    format = "<BH"
    dialects_string = b""
    for dialect in dialects:
        dialects_string += dialpad + bytes(dialect, "ascii") + b"\x00"
    format += str(len(dialects_string)) + "s"
    if lenwc:
        smb_negotiate = struct.pack(format, 0, len(dialects_string), dialects_string)
    else:
        smb_negotiate = struct.pack(format, 0, len(dialects_string) + 10, dialects_string)
    if lennb:
        net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb_header_packed + smb_negotiate))
    else:
        net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb_header_packed + smb_negotiate) + 10)
    return net_bios_header_packed + smb_header_packed + smb_negotiate

def smb_negotiate_request_unpack(data):
    global smb_negotiate_request

    format = "<BH"
    dialects_string_len = int(struct.unpack("<H", data[1:3])[0])
    dialects = data[4:].split(b"\x02")
    for dial in dialects:
        format += "B" + str(len(dial)) + "s"
    smb_negotiate_request["labels"] = ["Word Count", "Byte Count"] + ["Buffer Format", "Name"] * len(dialects)
    smb_negotiate_request["types"] = [int, int] + [str, str] * len(dialects)
    return struct.unpack(format, data[:(3 + dialects_string_len)]), (3 + dialects_string_len)

smb_negotiate_request = {
    "name": "smb_negotiate_request",
    "pack": smb_negotiate_request_pack,
    "unpack": smb_negotiate_request_unpack
}

def smb_negotiate_response_unpack(data):
    if len(data) < 37:
        raise struct.error("Data too short")
    
    chall_len = struct.unpack("<B", bytes([data[34]]))[0]
    sec_len = struct.unpack("<H", data[35:37])[0]
    fmt = "<BHBHHIIIIQHBH" + ((str(chall_len) + "s") if chall_len else "") + ((str(sec_len - chall_len) + "s") if sec_len - chall_len else "")
    return struct.unpack(fmt, data), 37 + sec_len

smb_negotiate_response = {
    "name": "smb_negotiate_response",
    "format": "<BHBHHIIIIQHBH",
    "labels": ["Word count", "Selected Index", "Security Mode", "Max mpx count", "Max VCs", "Buffer Size", "Max Raw Buffer", "Session Key", "Capabilities", "System Time", "Server Time Zone", "Challenge Length", "Byte Count", "Server UID", "Security Blob"],
    "types": [int, hex, hex, int, int, int, int, hex, lambda x: print_flags("SMB Negotiate Capabilities", 32, x, rev_labels=True), ms_time_to_unix, hex, int, int, str, parse_gssapi],
    "len": 37,
    "unpack": smb_negotiate_response_unpack
}

def smb_setupandx_request_auth_pack(server_info, server_chall, password="", domain="", user="", smbver=b'\xff', smbstr=b'SMB', smbcmd=0x73, ntstatus=0, flags1=0x18, flags2=0xc841, pidhigh=0, sig=0, reser1=0, tid=0, pidlow=0, uid=0, mid=3, wcnt=12, andxcmd=0xff, res1=0, andxoff=0, maxbuf=0xffff, maxmpxcnt=2, vcnum=1, sesskey=0, secbloblen=74, res2=0, caps=0x8000c054, bcnt=97, ntflags=0xe08a8205):
    smb_header_packed = struct.pack(smb_header["format"], smbver, smbstr, smbcmd, ntstatus, flags1, flags2, pidhigh, sig, reser1, tid, pidlow, uid, mid)
    gssapi = binascii.unhexlify("a16c306aa2680466")
    ntlm = struct.pack("<8sIHHIHHIHHIHHIHHIHHII", b"NTLMSSP\x00", 3, 0, 0, 64, 0, 0, 64, 0, 0, 64, 0, 0, 64, 22, 22, 64, 16, 16, 86, ntflags) # 0xe08a8205

    client_timestamp = b'\0' * 8
    client_challenge = bytes([ random.getrandbits(8) for i in range(0, 8) ])
    d = MD4()
    d.update(password.encode('UTF-16LE'))
    ntlm_hash = d.digest()
    response_key = hmac.new(ntlm_hash, (user.upper() + domain).encode('UTF-16LE'), 'md5').digest()
    temp = b'\x01\x01' + b'\0' * 6 + client_timestamp + client_challenge + b'\0' * 4 + server_info
    ntproofstr = hmac.new(response_key, server_chall + temp, 'md5').digest()
    session_key = hmac.new(response_key, ntproofstr, 'md5').digest()

    ntlm += interlace_zeroes(b"SMB-RESEARC")
    ntlm += session_key
    gssapi += ntlm
    smb_setup_packed = struct.pack(smb_setupandx_request["format"], wcnt, andxcmd, res1, andxoff, maxbuf, maxmpxcnt, vcnum, sesskey, len(gssapi), res2, caps, len(gssapi) + 22)
    smb_setup_packed += gssapi + b"\x00"
    smb_setup_packed += interlace_zeroes(b"Unix\x00") + interlace_zeroes(b"Samba\x00")
    net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb_header_packed + smb_setup_packed))
    return net_bios_header_packed + smb_header_packed + smb_setup_packed

def smb_setupandx_request_pack(smbver=b'\xff', smbstr=b'SMB', smbcmd=0x73, ntstatus=0, flags1=0x18, flags2=0xc841, pidhigh=0, sig=0, reser1=0, tid=0, pidlow=0, uid=0, mid=2, wcnt=12, andxcmd=0xff, res1=0, andxoff=0, maxbuf=0xffff, maxmpxcnt=2, vcnum=1, sesskey=0, secbloblen=74, res2=0, caps=0x8000c054, bcnt=97):
    smb_header_packed = struct.pack(smb_header["format"], smbver, smbstr, smbcmd, ntstatus, flags1, flags2, pidhigh, sig, reser1, tid, pidlow, uid, mid)
    smb_setup_packed = struct.pack(smb_setupandx_request["format"], wcnt, andxcmd, res1, andxoff, maxbuf, maxmpxcnt, vcnum, sesskey, secbloblen, res2, caps, bcnt)
    smb_setup_packed += binascii.unhexlify("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d53535000010000000582886200000000280000000000000028000000060100000000000f0055006e00690078000000530061006d00620061000000")
    net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb_header_packed + smb_setup_packed))
    return net_bios_header_packed + smb_header_packed + smb_setup_packed


def smb_setupandx_request_unpack(data):
    return struct.unpack(smb_setupandx_request["format"] + "75s10s12s", data), len(data)

smb_setupandx_request = {
    "name": "smb_setupandx_request",
    "format": "<BBBHHHHIHIIH",
    "labels": ["Word Count", "AndXCommand", "Reserved1", "AndXOffset", "Max Buffer", "Max Mpx Count", "VC Number", "Session Key", "Security Blob Length", "Reserved2", "Capabilities", "Byte Count", "Security Blob", "Native OS", "Native LAN Manager"],
    "types": [int, hex, hex, int, int, int, int, hex, int, int, lambda x: print_flags("SMB Negotiate Capabilities", 32, x, rev_labels=True), int, parse_gssapi, deinterlace_zeroes, deinterlace_zeroes],
    "pack": smb_setupandx_request_pack,
    "auth_pack": smb_setupandx_request_auth_pack,
    "unpack": smb_setupandx_request_unpack
}

def smb_setupandx_response_unpack(data):
    seclen = struct.unpack("<H", data[7:9])[0]
    datalen = struct.unpack("<H", data[9:11])[0]
    header = struct.unpack(smb_setupandx_response["format"], data[:smb_setupandx_response["len"]])
    secblob = struct.unpack("<" + str(seclen) + "s", data[smb_setupandx_response["len"]:smb_setupandx_response["len"] + seclen])
    rest_fields = struct.unpack("<" + str(datalen - seclen) + "s", data[smb_setupandx_response["len"] + seclen:])[0].split(b"\x00\x00")[:-1]
    smb_setupandx_response["labels"] = ["Word Count", "AndXCommand", "Reserved", "AndXOffset", "Action", "Security Blob Length", "Byte Count", "Security Blob", "Native OS", "Native LAN Manager"] + ["Additional"] * (max(0, (len(rest_fields) - 2)))
    smb_setupandx_response["types"] = [int, hex, hex, hex, hex, int, int, parse_gssapi, deinterlace_zeroes, deinterlace_zeroes] + [deinterlace_zeroes] * (max(0, (len(rest_fields) - 2)))
    return header + secblob + tuple(rest_fields), (smb_setupandx_response["len"] + datalen)

smb_setupandx_response = {
    "name": "smb_setupandx_response",
    "format": "<BBBHHHH",
    "labels": ["Word Count", "AndXCommand", "Reserved", "AndXOffset", "Action", "Security Blob Length", "Byte Count", "Security Blob", "Native OS", "Native LAN Manager"],
    "types": [int, hex, hex, hex, hex, int, int, parse_gssapi, deinterlace_zeroes, deinterlace_zeroes],
    "len": 11,
    "unpack": smb_setupandx_response_unpack
}

def smb2_negotiate_request_pack(dialects, smbver=b"\xfe", smbstr=b"SMB", hdlen=64, credchrg=1, status=0, command=0, credgranted=1, flags1=0x0, chainoff=0, mid=1, pid=0, tid=0, sid=0, sign=b"", strctsize=36, secmode=1, res=0, caps=0x0, guid=b"94a99c9e5c186c4cab61eca2a7ebe238"):
    smb2_header_packed = struct.pack(smb2_header["format"], smbver, smbstr, hdlen, credchrg, status, command, credgranted, flags1, chainoff, mid, pid, tid, sid, sign)    
    smb2_negotiate_request_packed = struct.pack(smb2_negotiate_request["format"], strctsize, len(dialects), secmode, res, caps, binascii.unhexlify(guid), 0x64 + len(dialects) * 2 + 8 - (((len(dialects) * 2) + 0x64) % 8), 2, 0) + struct.pack("<" + "H" * len(dialects), *dialects) + b"\x00" * (8 - (((len(dialects) * 2) + 0x64) % 8))
    smb2_negotiate_request_packed += binascii.unhexlify("0100260000000000010020000100b7b343261a7e2129bf9c7fcf41fb3f2ef05e21381ae4cf4029f1ee9c1a938c0000000200060000000000020001000200")
    net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb2_header_packed + smb2_negotiate_request_packed))
    return net_bios_header_packed + smb2_header_packed + smb2_negotiate_request_packed

smb2_negotiate_request = {
    "name": "smb2_negotiate_request",
    "format": "<HHHHI16sIHH",
    "labels": ["Structure Size", "Dialect Count", "Security Mode", "Reserved", "Capability Flags", "Client GUID", "Negotiate Context Offset", "NegotiateContextCount", "Reserved", "SecBuffer + NegContext"],
    "types": [int, int, int, int, lambda x: print_flags("SMB2 Negotiate Capabilities", 32, x, rev_labels=True), str, hex, int, hex, str],
    "len": 36,
    "unpack": lambda x: (struct.unpack("<HHHHI16sIHH" + str(len(x) - 36) + "s", x), len(x)),
    "pack": smb2_negotiate_request_pack
}

smb2_negotiate_response = {
    "name": "smb2_negotiate_response",
    "format": "<HBBHH16siiiiQQHHi",
    "labels": ["Structure Size", "Security Mode", "Padding", "Dialect", "Negotiate Context Count", "Server GUID", "Capability Flags", "Maximum Transaction Size", "Maximum Read Size", "Maximum Write Size", "Current Time", "Boot Time", "Blob Offset", "Blob Length", "Padding", "Security Blob"],
    "types": [int, int, int, resolve_dialect, int, str, lambda x: print_flags("SMB2 Negotiate Capabilities", 32, x, rev_labels=True), int, int, int, ms_time_to_unix, ms_time_to_unix, int, int, int, parse_gssapi],
    "len": 138,
    "unpack": lambda x: generic_extension_unpack("<HBBHH16siiiiQQHHi", "<H", 64, 58, 60, x)
}

def smb2_setup_auth_request_pack(server_info, server_chall, sid, user="", password="", domain="", smbver=b"\xfe", smbstr=b"SMB", hdlen=64, credchrg=1, status=0, command=1, credgranted=1, flags1=0x0, chainoff=0, mid=3, pid=0, tid=0, sign=b"", strctsize=0x19, flags2=0, secmode=1, caps=0, chan=0, sbo=0x58, previd=0, ntflags=0xe08a8205):
    smb2_header_packed = struct.pack(smb2_header["format"], smbver, smbstr, hdlen, credchrg, status, command, credgranted, flags1, chainoff, mid, pid, tid, sid, sign)
    gssapi = binascii.unhexlify("a16c306aa2680466")
    ntlm = struct.pack("<8sIHHIHHIHHIHHIHHIHHII", b"NTLMSSP\x00", 3, 0, 0, 64, 0, 0, 64, 0, 0, 64, 0, 0, 64, 22, 22, 64, 16, 16, 86, ntflags) # 0xe08a8205

    client_timestamp = b'\0' * 8
    client_challenge = bytes([ random.getrandbits(8) for i in range(0, 8) ])
    d = MD4()
    d.update(password.encode('UTF-16LE'))
    ntlm_hash = d.digest()
    response_key = hmac.new(ntlm_hash, (user.upper() + domain).encode('UTF-16LE'), 'md5').digest()
    temp = b'\x01\x01' + b'\0' * 6 + client_timestamp + client_challenge + b'\0' * 4 + server_info
    ntproofstr = hmac.new(response_key, server_chall + temp, 'md5').digest()
    session_key = hmac.new(response_key, ntproofstr, 'md5').digest()

    ntlm += interlace_zeroes(b"SMB-RESEARC")
    ntlm += session_key
    gssapi += ntlm

    smb2_setup_packed = struct.pack(smb2_setup_request["format"], strctsize, flags2, secmode, caps, chan, sbo, len(gssapi), previd)
    smb2_setup_packed += gssapi
    net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb2_header_packed + smb2_setup_packed))
    return net_bios_header_packed + smb2_header_packed + smb2_setup_packed

def smb2_setup_request_pack(smbver=b"\xfe", smbstr=b"SMB", hdlen=64, credchrg=1, status=0, command=1, credgranted=1, flags1=0x0, chainoff=0, mid=2, pid=0, tid=0, sid=0, sign=b"", strctsize=0x19, flags2=0, secmode=1, caps=0, chan=0, sbo=0x58, previd=0):
    smb2_header_packed = struct.pack(smb2_header["format"], smbver, smbstr, hdlen, credchrg, status, command, credgranted, flags1, chainoff, mid, pid, tid, sid, sign)
    client_str = b"\x00research_scan"
    client_str = b""
    ntlm = struct.pack("<8sIIHHIHHIQ", b"NTLMSSP", 1, 0xe280a205, 0, 0, 0, len(client_str), len(client_str), 40, 0xf00000017720006) + client_str
    gssapi = binascii.unhexlify("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04") + struct.pack("B", len(ntlm)) + ntlm
    smb2_setup_packed = struct.pack(smb2_setup_request["format"], strctsize, flags2, secmode, caps, chan, sbo, len(gssapi), previd) + gssapi
    #smb2_setup_packed += binascii.unhexlify("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04424e544c4d5353500001000000058280e20000000000000000001a001a0000002a060072170000000f")
    net_bios_header_packed = struct.pack(net_bios_header["format"], len(smb2_header_packed + smb2_setup_packed))
    return net_bios_header_packed + smb2_header_packed + smb2_setup_packed

smb2_setup_request = {
    "name": "smb2_setup_request",
    "format": "<HBBIIHHQ",
    "labels": ["Structure Size", "Flags", "Security Mode", "Capabilities", "Channel", "Security Buffer Offset", "Security Buffer Length", "Previous Session ID", "Security Buffer"],
    "types": [int, lambda x: print_flags("SMB2 Session Setup Request", 8, x, rev_labels=True), int, lambda x: print_flags("SMB2 Negotiate Capabilities", 32, x, rev_labels=True), hex, int, int, hex, parse_gssapi],
    "len": 24,
    "unpack": lambda x: generic_extension_unpack("<HBBIIHHQ", "<H", 24, 14, 16, x),
    "pack": smb2_setup_request_pack,
    "auth_pack": smb2_setup_auth_request_pack
}

smb2_setup_response = {
    "name": "smb2_setup_response",
    "format": "<HHHH",
    "labels": ["Structure Size", "Session Flags", "Security Buffer Offset", "Security Buffer Length", "Security Blob"],
    "types": [int, lambda x: print_flags("SMB2 Session Setup Response", 32, x), int, int, parse_gssapi],
    "len": 8,
    "unpack": lambda x: generic_extension_unpack("<HHHH", "<H", 8, 6, 8, x)
}

def unpack_response(response, request=False):
    if isinstance(response, int):
        return response
    elif len(response) == 0:
        return 0
    elif len(response) < 5:
        return 5
    else:
        try:
            if request:
                headers = [net_bios_header, smb_header, smb_negotiate_request]
                if response[4] == 0xff:
                    if response[8] == 0x72:
                        headers = [net_bios_header, smb_header, smb_negotiate_request]
                    elif response[8] == 0x73:
                        headers = [net_bios_header, smb_header, smb_setupandx_request]                    
                elif response[4] == 0xfe:
                    command = struct.unpack("<H", response[16:18])[0]
                    if command == 0:
                        headers = [net_bios_header, smb2_header, smb2_negotiate_request]
                    elif command == 1:
                        headers = [net_bios_header, smb2_header, smb2_setup_request]
            elif response[4] == 0xff:
                headers = [net_bios_header, smb_header, smb_negotiate_response]
                if response[8] == 0x72:
                    headers = [net_bios_header, smb_header, smb_negotiate_response]
                elif response[8] == 0x73:
                    headers = [net_bios_header, smb_header, smb_setupandx_response]
            elif response[4] == 0xfe:
                headers = [net_bios_header, smb2_header, smb2_negotiate_response]
                command = struct.unpack("<H", response[16:18])[0]
                if command == 0:
                    headers = [net_bios_header, smb2_header, smb2_negotiate_response]
                elif command == 1:
                    headers = [net_bios_header, smb2_header, smb2_setup_response]
            else:
                    return 5
        except (IndexError, struct.error):
            return 5

        ret = []
        offset = 0
        for header in headers:
            try:
                data = header["unpack"](response[offset:])
                offset += data[1]
                data = data[0]
                ret.append(data)
            except struct.error as e:
                ret.append((e, response[offset:]))
        
        return headers, ret

def print_response(response, request=False, outfile=sys.stdout):
    data_raw = unpack_response(response, request)

    if data_raw in range(0, 6):
        print("Error:", error_codes_inv[str(data_raw)])
        return

    try:
        headers = data_raw[0]
        data = data_raw[1]
    except TypeError:
        print(response)

    for tup in zip(data, headers):
        header_data = tup[0]
        header = tup[1]

        print(header["name"], file=outfile)
        if isinstance(header_data[0], Exception):
            print("\t", "Exception:", header_data[0], file=outfile)
            print("\t", "Data:", header_data[1], file=outfile)
            continue
        for el in zip(header_data, header["labels"], header["types"]):
            print_data = el[2](el[0])
            if isinstance(print_data, list):
                print("\t", "{}: {}".format(el[1], print_data[0]), file=outfile)
                for el2 in print_data[1:]:
                    print("\t\t", el2[0], ":", el2[1], file=outfile)
            else:
                print("\t", el[1], ":", print_data, file=outfile)

standard_dialects = ["NT LANMAN 1.0", "NT LM 0.12", "SMB 2.???", "PC NETWORK PROGRAM 1.0", "MICROSOFT NETWORKS 1.03", "MICROSOFT NETWORKS 3.0", "LANMAN1.0", "LM1.2X002", "DOS LANMAN2.1", "LANMAN2.1", "Samba", "SMB 2.002"]
standard_dialects_smb2 = [0x202, 0x210, 0x222, 0x224, 0x300, 0x302, 0x310, 0x311]