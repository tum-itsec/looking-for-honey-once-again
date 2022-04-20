import os
import sys
import json
import binascii
import itertools
import functools
import hashlib
import gmpy2
import argparse

from SMB_structs import *
from datetime import datetime

class SMBDiff:
    def __init__(self):
        self.min_request = None
        self.min_responses = None
        self.min_similarity = 1
        self.simil_overall = 0
        self.totalcount = 0
        self.connxor = {"0": 0, "1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
        self.connxor_cnt = 0
        self.connboth = {"0": 0, "1": 0, "2": 0, "3": 0, "4": 0, "5": 0}
        self.connboth_cnt = 0
        self.headerxor = 0
        self.errorxor = 0
        self.errorboth = 0
        self.errordiff = 0
        self.dotcnt = 0
        self.dotcnt_diff = 0
        self.field_cnt = 0
        self.field_cnts = {}

    def __eq__(self, other):
        conds = [
            self.connxor == other.connxor,
            self.connboth == other.connboth,
            self.headerxor == other.headerxor,
            self.errorxor == other.errorxor,
            self.errorboth == other.errorboth,
            self.errordiff == other.errordiff,
            self.dotcnt == other.dotcnt,
            self.dotcnt_diff == other.dotcnt_diff,
            self.field_cnt == other.field_cnt,
            self.field_cnts == other.field_cnts
        ]
        return all(conds)

def iserror(el):
    if isinstance(el, tuple):
        return isinstance(el[0], Exception)
    return False

def compare_fields(stats, data1, data2):
    field_cnt = 1
    diff_fields = [
        "SMB Version",
        "Server Component",
        "NT Status",
        "Command",
        #"Flags 1",
        "Flags2",
        "Signature",
        "Process ID",
        "Reserved",
        "Tree ID",
        "User ID",
        "Multiplex ID",
        #"Selected Index",
        #"Security Mode",
        "Max VCs",
        "Session Key",
        "Capabilities",
        "AndXCommand",
        "AndXReserved",
        "Action",
        #"Credit Charge",
        "NT Status",
        "Command",
        #"Credits granted",
        "Flags",
        "Chain Offset",
        "Message ID",
        "Process ID/Reserved",
        "Tree ID",
        "Session ID",
        "Signature",
        #"Padding",
        "Dialect"
    ]

    for tup in zip(data1, data2):
        log = False
        if tup[0][0] == "Security Blob":
            please_ignore = b"$not_defined_in_RFC4178@please_ignore"
            win7_blob = b'`(\x06\x06+\x06\x01\x05\x05\x02\xa0\x1e0\x1c\xa0\x1a0\x18\x06\n+\x06\x01\x04\x01\x827\x02\x02\x1e\x06\n+\x06\x01\x04\x01\x827\x02\x02\n'
            win10_blob = lambda x: (b"NEGOEXTS" in x) and (b"Token Signing Public Key" in x)
            if (win10_blob(tup[0][1])) ^ (win10_blob(tup[1][1])):
                field_cnt += 1
                log = True
            if (tup[0][1] == win7_blob) ^ (tup[1][1] == win7_blob):
                field_cnt += 1
                log = True
            if (please_ignore in tup[0][1]) ^ (please_ignore in tup[1][1]):
                field_cnt += 1
                log = True
            if (tup[0][1] == 0) ^ (tup[1][1] == 0):
                field_cnt += 1
                log = True
            else:
                sec_data1 = parse_gssapi(tup[0][1])
                sec_data2 = parse_gssapi(tup[1][1])

                if isinstance(sec_data1, bytes) or isinstance(sec_data2, bytes):
                    continue
                elif (len(sec_data1) == 6) ^ (len(sec_data2) == 6):
                    field_cnt += 1
                    log = True
                else:
                    for el in zip(sec_data1, sec_data2):
                        if el[0][0] == "Reserved":
                            if (el[0][1] != 0) ^ (el[1][1] != 0):
                                field_cnt += 1
                                log = True
                                break
                        elif el[0][0] == "Target Name":
                            if (el[0][1] == b"") ^ (el[1][1] == b""):
                                field_cnt += 1
                                log = True
                                break
                        elif el[0][0] == "NTLM Server Challenge":
                            if (el[0][1] == 0) ^ (el[1][1] == 0):
                                field_cnt += 1
                                log = True
                                break
                            
        elif tup[0][0] == "Server GUID":
            guid = b"AAAAAAAAAAAAAAAA"
            if (tup[0][1] == guid) ^ (tup[1][1] == guid):
                field_cnt += 1
                log = True
        elif tup[0][0] == "Selected Index":
            if (tup[0][1] > 1) ^ (tup[1][1] > 1):
                field_cnt += 1
                log = True
        #elif tup[0][0] == "Boot Time":
        #    if (tup[0][1] != 0) ^ (tup[1][1] != 0):
        #        field_cnt += 1
        #        log = True
        elif tup[0][0] in diff_fields:
            if tup[0][1] != tup[1][1]:
                field_cnt += 1
                log = True
        
        if log:
            if tup[0][0] in stats.field_cnts:
                stats.field_cnts[tup[0][0]] += 1
            else:
                stats.field_cnts[tup[0][0]] = 1
            stats.field_cnt += 1
    
    stats.dotcnt_diff += int(field_cnt > 1)
    
    return 1 / field_cnt


def dot(tup1, tup2):
    return functools.reduce(lambda x, y: x + (y[0] * y[1]), list(zip(tup1, tup2)), 0)

def normalize(tup):
    square = gmpy2.mpz(functools.reduce(lambda x, y: x + y * y, tup, 0))
    return gmpy2.sqrt(square)

def bytes_to_int(byt):
    if len(byt) > 4:
        return int(hashlib.md5(byt).hexdigest()[:8], 16)
    else:
        byt = (4 - len(byt)) * b"\x00" + byt
        return struct.unpack("<L", byt)[0]

def flatten_tuples(tuptup):
    return tuple([el for tup in tuptup for el in tup])

def compare_responses(stats, resp1, resp2):
    stats.totalcount += 1

    if isinstance(resp1, int) and isinstance(resp2, int):
        """if resp1 == resp2:
            stats.connboth[str(resp1)] += 1
            stats.connboth_cnt += 1
            return 1
        else:
            stats.connxor[str(resp1)] += 1
            stats.connxor_cnt += 1
            return 0"""
        stats.connboth_cnt += 1
        return 1
    if isinstance(resp1, int) ^ isinstance(resp2, int):
        if isinstance(resp1, int):
            stats.connxor[str(resp1)] += 1
        else:
            stats.connxor[str(resp2)] += 1
        stats.connxor_cnt += 1
        return 0
    
    for el in zip(resp1[0], resp2[0]):
        if el[0]["name"] != el[1]["name"]:
            stats.headerxor += 1
            return 0
    
    resp1_fields = []
    for el in zip(resp1[0], resp1[1]):
        if not iserror(el[1]):
            resp1_fields += list(zip(el[0]["labels"], el[1]))

    resp2_fields = []
    for el in zip(resp2[0], resp2[1]):
        if not iserror(el[1]):
            resp2_fields += list(zip(el[0]["labels"], el[1]))

    for el in zip(resp1[1], resp2[1]):
        if iserror(el[0]) ^ iserror(el[1]):
            stats.errorxor += 1
            return 0
        if iserror(el[0]) and iserror(el[1]):
            if el[0][1] == el[1][1]:
                stats.errorboth += 1
                stats.dotcnt += 1
                return 0.5 + 0.5 * compare_fields(stats, resp1_fields, resp2_fields)
            else:
                stats.errordiff += 1
                stats.dotcnt += 1
                return 0.5 * compare_fields(stats, resp1_fields, resp2_fields)

    stats.dotcnt += 1

    return compare_fields(stats, resp1_fields, resp2_fields)

def compare_responses_cosine(stats, resp1, resp2):
    stats.totalcount += 1

    if isinstance(resp1, int) ^ isinstance(resp2, int):
        if isinstance(resp1, int):
            stats.connxor[str(resp1)] += 1
        else:
            stats.connxor[str(resp2)] += 1
        stats.connxor_cnt += 1
        return 0
    elif isinstance(resp1, int) and isinstance(resp2, int):
        stats.connboth[str(resp1)] += 1
        stats.connboth_cnt += 1
        return 1
    
    for el in zip(resp1[0], resp2[0]):
        if el[0]["name"] != el[1]["name"]:
            stats.headerxor += 1
            return 0
    
    for el in zip(resp1[1], resp2[1]):
        if iserror(el[0]) ^ iserror(el[1]):
            stats.errorxor += 1
            return 0
        if iserror(el[0]) and iserror(el[1]):
            stats.errorboth += 1
            return 1

    stats.dotcnt += 1

    resp1 = flatten_tuples(resp1[1])
    resp2 = flatten_tuples(resp2[1])

    resp1_bytes = ()
    resp2_bytes = ()

    for el in resp1:
        if isinstance(el, bytes):
            resp1_bytes += (bytes_to_int(el),)
        else:
            resp1_bytes += (el,)

    for el in resp2:
        if isinstance(el, bytes):
            resp2_bytes += (bytes_to_int(el),)
        else:
            resp2_bytes += (el,)

    try:
        dotp = dot(resp1_bytes, resp2_bytes)
    except TypeError:
        print(resp1_bytes)
        print(resp2_bytes)
    
    norm1 = normalize(resp1_bytes)
    norm2 = normalize(resp2_bytes)

    sim = dotp / int(norm1 * norm2)
    return sim


def diff_files(files1, files2, multi_mode=True, progress=True):
    counter = 1

    doublemode = files2 == []

    files2 = list(files1) if doublemode else files2

    try:
        fds1 = [open(os.path.join(PATH, (PREFIX + file))) for file in files1]
        fds2 = [open(os.path.join(PATH, (PREFIX + file))) for file in files2]
    except FileNotFoundError as e:
        print(e)
        print("One or more files not found. Aborting")
        sys.exit(1)

    stats = SMBDiff()

    start = datetime.now()

    while True:
        if progress:
            if counter % 0x10000 == 0:
                sys.stderr.write("Progress: {:.2f}%\r".format((counter / 851968) * 100))
                sys.stderr.flush()

        lines1 = [f.readline().strip("\n") for f in fds1]
        lines2 = [f.readline().strip("\n") for f in fds2]
        lines_split1 = [line.split(": ") for line in lines1]
        lines_split2 = [line.split(": ") for line in lines2]
    
        try:
            requests1 = [el[0] for el in lines_split1]
            responses1 = [el[1] for el in lines_split1]
            responses2 = [el[1] for el in lines_split2]
        except IndexError:
            if progress:
                print("\nDone.", file=sys.stderr)
            break

        counter += 1

        if not multi_mode:
            response_data1 = [int(el) if len(el) == 1 else unpack_response(binascii.unhexlify(el)) for el in responses1]
            response_data2 = [int(el) if len(el) == 1 else unpack_response(binascii.unhexlify(el)) for el in responses2]

            if doublemode:
                combinations = [(el[0][1], el[1][1]) for el in filter(lambda x: x[0][0] != x[1][0], list(itertools.product(list(enumerate(response_data1)), list(enumerate(response_data2)))))]
            else:
                combinations = list(itertools.product(response_data1, response_data2))

            simil_av = 0
            for el in combinations:
                simil = compare_responses(stats, el[0], el[1])
                simil_av += simil
        else:
            response_data1 = [[int(el2) if len(el2) == 1 else unpack_response(binascii.unhexlify(el2)) for el2 in json.loads(el)] for el in responses1]
            response_data2 = [[int(el2) if len(el2) == 1 else unpack_response(binascii.unhexlify(el2)) for el2 in json.loads(el)] for el in responses2]

            if doublemode:
                combinations = [(el[0][1], el[1][1]) for el in filter(lambda x: x[0][0] != x[1][0], list(itertools.product(list(enumerate(response_data1)), list(enumerate(response_data2)))))]
            else:
                combinations = list(itertools.product(response_data1, response_data2))

            simil_av = 0
            for el in combinations:
                packets = list(zip(el[0], el[1]))
                packets_cnt = len(packets)
                packets_simil = 0
                
                for tup in packets:
                    simil = compare_responses(stats, tup[0], tup[1])
                    packets_simil += simil

                packets_simil /= packets_cnt
                simil_av += packets_simil

        simil_av /= len(combinations)
        stats.simil_overall += simil_av
        
        if simil_av < stats.min_similarity:
            stats.min_similarity = simil_av
            stats.min_request = requests1[0]
            stats.min_responses = responses1 + responses2

    stats.simil_overall /= (counter - 1)

    if progress:
        print("Elapsed time:", datetime.now() - start, file=sys.stderr)

    return stats

def print_stats(stats, outfile=sys.stdout):
    print("Conn xor: {:.2f}% ({})".format((stats.connxor_cnt / stats.totalcount) * 100, stats.connxor_cnt), file=outfile)
    if stats.connxor_cnt:
        for el in stats.connxor.keys():
            print("\t{}: {:.2f}%".format(error_codes_inv[el], (stats.connxor[el] / stats.connxor_cnt) * 100))
    print("Conn both: {:.2f}% ({})".format((stats.connboth_cnt / stats.totalcount) * 100, stats.connboth_cnt), file=outfile)
    """if stats.connboth_cnt:
        for el in stats.connboth.keys():
            print("\t{}: {:.2f}%".format(error_codes_inv[el], (stats.connboth[el] / stats.connboth_cnt) * 100))"""
    print("Header diff: {:.2f}% ({})".format((stats.headerxor / stats.totalcount) * 100, stats.headerxor), file=outfile)
    print("Error xor: {:.2f}% ({})".format((stats.errorxor / stats.totalcount) * 100, stats.errorxor), file=outfile)
    print("Error both: {:.2f}% ({})".format((stats.errorboth / stats.totalcount) * 100, stats.errorboth), file=outfile)
    print("Error diff: {:.2f}% ({})".format((stats.errordiff / stats.totalcount) * 100, stats.errordiff), file=outfile)
    print("Antwort: {:.2f}% ({})".format((stats.dotcnt / stats.totalcount) * 100, stats.dotcnt), file=outfile)
    if stats.dotcnt:
        print("Nicht identisch: {:.2f}% ({})".format((stats.dotcnt_diff / stats.dotcnt) * 100, stats.dotcnt_diff), file=outfile)
    print("Diff Fields: {}".format(stats.field_cnt), file=outfile)
    for el in stats.field_cnts.keys():
        print("    {}: {:.2f}% ({})".format(el, (stats.field_cnts[el] / stats.field_cnt) * 100, stats.field_cnts[el]), file=outfile)

PATH = "/home/lion/Data/Outsource/SMB_responses"
PREFIX = "SMB_responses_"

gmpy2.get_context().precision = 2048

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--show-stats", action="store_true", dest="show_stats")
    parser.add_argument("--single-packet-mode", action="store_false", dest="multi_mode")
    args = parser.parse_args()

    files1 = ["localhost_samba", "localhost_samba_smb1", "localhost_win10", "localhost_win7", "localhost_winxp", "localhost_smbpot", "localhost_dionaea"]
    files2 = []


    files1 = [f + "_multipacket.hex" if args.multi_mode else f + ".hex" for f in files1]
    files2 = [f + "_multipacket.hex" if args.multi_mode else f + ".hex" for f in files2]

    stats = diff_files(files1, files2, multi_mode=args.multi_mode)

    if stats.min_responses is None:
        print("No distinctive request found.")
    else:
        print("Distinctive request:")
        for el in json.loads(stats.min_request):
            print_response(binascii.unhexlify(el), request=True)

        print()
        print("Average similarity:", stats.min_similarity)
        print()

        for el in zip(stats.min_responses, files1 + files2):
            print(el[1], ":")
            for el2 in json.loads(el[0]):
                    print_response(el2 if len(el2) == 1 else binascii.unhexlify(el2))
            print()

        print(stats.min_request)
        for el in zip(files1 + files2, stats.min_responses):
            print(el)

    if args.show_stats:
        print()
        print_stats(stats)        
