import os
import sys
import json
import argparse
import binascii

from SMB_classify import classify, extract_nativeos
from SMB_diff import print_stats, iserror
from SMB_logincheck import check_guest_login
from SMB_structs import unpack_response
from classification import smb_classif_columns, init_smb_row, print_smb_row

parser = argparse.ArgumentParser()
parser.add_argument("path")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose")
args = parser.parse_args()

NUM_PACKETS = 4

perc_stats = { "Premature session exit": (0, dict()) }
guest_login_cnt = {
    "Error": 0,
    "No data": 0,
    "Empty response": 0,
    "Invalid response": 0,
    "Invalid version": 0,
    "Premature session exit": 0,
    "Premature session exit v1": 0,
    "Premature session exit v1 802.1X Auth": 0,
    "Premature session exit v2": 0,
    "Guest": 0,
    "No guest": 0
}

smbv1support_cnt = {
    "Error": 0,
    "No data": 0,
    "Empty response": 0,
    "Invalid response": 0,
    "Invalid version": 0,
    "Session close": 0,
    "SMBv1 Support": 0,
    "No SMBv1 Support": 0
}

smbv3support_cnt = {
    "Error": 0,
    "No data": 0,
    "Empty response": 0,
    "Invalid response": 0,
    "Invalid version": 0,
    "Session close": 0,
    "SMBv3 Support": 0,
    "No SMBv3 Support": 0
}

dup_100 = 0
dup_class = 0
classifications_total = 0
smbv1_total = 0
smbv3_total = 0
guestlogin_total = 0
full_responses_total = 0
partial_responses_total = 0

cfn = os.path.join(args.path, "classification.csv")
dfn = os.path.join(args.path, "response_dump.csv")
ifn = os.path.join(args.path, "input")

ip_data = dict()

with open(ifn) as f:
    ips_total = len(list(f))

with open(dfn) as f:
    files_total = len(list(f))

with open(dfn) as f, open(cfn, "w") as fc:
    for i, line in enumerate(f):
        if i % 1000 == 0:
            sys.stderr.write("{:.2f}%\r".format((i / files_total) * 100))

        ip, guestcheck, smbv1check, smbv3check, resp = line.split(", ", 4)
        resp = json.loads(resp)

        if not ip in ip_data:
            ip_data[ip] = init_smb_row()
            ip_data[ip]["ip"] = ip
            ip_data[ip]["responses"] = 0

        if guestcheck == "True":
            guest_hint = ""

            guestlogin_total += 1
            if len(resp) == 0:
                guest_resp = "Empty response"
            elif len(resp) == 1:
                guest_resp = "Premature session exit"
            elif len(resp[0]["data"]) < 5:
                guest_resp = "Invalid response"
            else:
                resp_last = resp[-1]
                guest_login = check_guest_login(unpack_response(resp_last["exception"] if resp_last["exception"] >= 0 else binascii.unhexlify(resp_last["data"])))

                if resp[0]["data"][8:10] == "ff":
                    native_os = extract_nativeos([el["exception"] if el["exception"] >= 0 else binascii.unhexlify(el["data"]) for el in resp])
                    if native_os:
                        guest_hint = native_os

                if "unavailable" in guest_login:
                    guest_resp = "No guest"
                elif "available" in guest_login:
                    guest_resp = "Guest"
                else:                    
                    if resp[0]["data"][8:10] == "ff":
                        if len(resp) < 3:
                            try:
                                if unpack_response(binascii.unhexlify(resp[1]["data"]))[1][1][3] == 0x50001:
                                    guest_resp = "Premature session exit v1 802.1X Auth"
                            except (TypeError, IndexError, binascii.Error):
                                pass
                            guest_resp = "Premature session exit v1"
                    elif resp[0]["data"][8:10] == "fe":
                        if len(resp) < 4:
                            guest_resp = "Premature session exit v2"
                    else:
                        guest_resp = "Invalid version"

                    if not guest_resp:
                        guest_resp = "Error"

            ip_data[ip]["guestlogin"] = guest_resp
            if "hint" in ip_data[ip]:
                if guest_hint and ip_data[ip]["hint"] and guest_hint != ip_data[ip]["hint"]:
                    print("Warning, unmatching lm strings:", ip, repr(ip_data[ip]["hint"]), repr(guest_hint), binascii.hexlify(ip_data[ip]["hint"].encode()), binascii.hexlify(guest_hint.encode()))
                ip_data[ip]["hint"] = guest_hint
            else:
                ip_data[ip]["hint"] = guest_hint

            ip_data[ip]["responses"] += 1
        elif smbv1check == "True":
            resp_data = unpack_response(resp[0]["exception"] if resp[0]["exception"] >= 0 else binascii.unhexlify(resp[0]["data"]))

            smbv1_total += 1
            if len(resp) == 0:
                smbv1_resp = "Empty response"
            elif isinstance(resp_data, int):
                smbv1_resp = "Session close"
            else:
                if iserror(resp_data[1][2]):
                    smbv1_resp = "No SMBv1 Support"
                else:
                    smbv1_resp = "SMBv1 Support"
            ip_data[ip]["smbv1support"] = smbv1_resp

            ip_data[ip]["responses"] += 1
        elif smbv3check == "True":
            resp_data = unpack_response(resp[0]["exception"] if resp[0]["exception"] >= 0 else binascii.unhexlify(resp[0]["data"]))

            smbv3_total += 1
            if len(resp) == 0:
                smbv3_resp = "Empty response"
            elif isinstance(resp_data, int):
                smbv3_resp = "Session close"
            else:
                if iserror(resp_data[1][2]):
                    smbv3_resp = "No SMBv3 Support"
                else:
                    if resp_data[1][1][0] != b"\xfe":
                        smbv3_resp = "No SMBv3 Support"
                    else:
                        smbv3_resp = "SMBv3 Support"
            ip_data[ip]["smbv3support"] = smbv3_resp

            ip_data[ip]["responses"] += 1
        else:
            data = [el["exception"] if el["exception"] >= 0 else binascii.unhexlify(el["data"]) for el in resp]
            class_data, hint = classify(data, True)

            classifications_total += 1

            if not class_data:
                ip_data[ip]["class"] = "Premature session exit"
                ip_data[ip]["class_simil"] = 1
            else:
                class_simil = class_data[0][1]
                class_class = class_data[0][0]
                dups = 1
                while class_data[dups][1] == class_simil:
                    class_class += " / " + class_data[dups][0]
                    dups += 1
                    if dups == len(class_data):
                        break

                if dups > 1:
                    dup_class += 1

                if class_data[1][1] == 1:
                    dup_100 += 1

                ip_data[ip]["class"] = class_class
                ip_data[ip]["class_simil"] = class_simil
                if hint:
                    if "hint" in ip_data[ip] and ip_data[ip]["hint"] and hint != ip_data[ip]["hint"]:
                        print("Warning, unmatching lm strings:", ip, repr(ip_data[ip]["hint"]), repr(hint), binascii.hexlify(ip_data[ip]["hint"].encode()), binascii.hexlify(hint.encode()))
                    else:
                        ip_data[ip]["hint"] = hint

            ip_data[ip]["responses"] += 1
        
        if ip_data[ip]["responses"] == NUM_PACKETS:
            full_responses_total += 1
            fc.write(f"{print_smb_row(ip_data[ip])}\n")

            class_key = ip_data[ip]['class'] + (f" ({ip_data[ip]['hint']})" if ip_data[ip]["hint"] else "")
            class_simil = ip_data[ip]['class_simil']
            if not class_key in perc_stats:
                perc_stats[class_key] = (0, dict())
            perc_stats[class_key] = (perc_stats[class_key][0] + 1, perc_stats[class_key][1])
            if not class_simil in perc_stats[class_key][1]:
                perc_stats[class_key][1][class_simil] = 1
            else:
                perc_stats[class_key][1][class_simil] += 1

            guest_login_cnt[ip_data[ip]['guestlogin']] += 1
            smbv1support_cnt[ip_data[ip]['smbv1support']] += 1
            smbv3support_cnt[ip_data[ip]['smbv3support']] += 1
            del ip_data[ip]

with open(cfn, "a") as f:
    for ip in ip_data:
        partial_responses_total += 1

        if not ip_data[ip]["class"]:
            ip_data[ip]["class"] = "No Data"
            ip_data[ip]["class_simil"] = 1
        if not "hint" in ip_data[ip]:
            ip_data[ip]["hint"] = ""
        if not ip_data[ip]["guestlogin"]:
            ip_data[ip]["guestlogin"] = "No data"
        if not ip_data[ip]["smbv1support"]:
            ip_data[ip]["smbv1support"] = "No data"
        if not ip_data[ip]["smbv3support"]:
            ip_data[ip]["smbv3support"] = "No data"

        class_key = ip_data[ip]['class'] + (f" ({ip_data[ip]['hint']})" if ip_data[ip]["hint"] else "")
        class_simil = ip_data[ip]['class_simil']
        if not class_key in perc_stats:
            perc_stats[class_key] = (0, dict())
        perc_stats[class_key] = (perc_stats[class_key][0] + 1, perc_stats[class_key][1])
        if not class_simil in perc_stats[class_key][1]:
            perc_stats[class_key][1][class_simil] = 1
        else:
            perc_stats[class_key][1][class_simil] += 1

        guest_login_cnt[ip_data[ip]['guestlogin']] += 1
        smbv1support_cnt[ip_data[ip]['smbv1support']] += 1
        smbv3support_cnt[ip_data[ip]['smbv3support']] += 1

        f.write(f"{print_smb_row(ip_data[ip])}\n")

print("Summary stats:")
print("\tTotal number of input IPs:", ips_total)
print("\tTotal number of unique reached IPs:", full_responses_total + partial_responses_total)
print("\tTotal number of full responses:", full_responses_total)
print("\tTotal number of only partial responses:", partial_responses_total)
print()

guest_login_cnt["Data"] = guest_login_cnt["Guest"] + guest_login_cnt["No guest"]
print("Guest login stats:")
print("\tTotal number of responses to guest login packet:", guestlogin_total)
for key, val in guest_login_cnt.items():
    if (key == "Guest" or key == "No guest") and guest_login_cnt[key]:
        print("\t{}: {} ({:.2f}%) ({:.2f}%)".format(key, val, ((val / guestlogin_total) * 100), ((val / guest_login_cnt["Data"]) * 100)))
    elif key == "Premature session exit v1 802.1X Auth" and guest_login_cnt[key]:
        print("\t802.1X Auth: {} ({:.2f}%) ({:.2f}%)".format(val, ((val / guestlogin_total) * 100), ((val / guest_login_cnt["Premature session exit v1"]) * 100)))
    else:
        print("\t{}: {} ({:.2f}%)".format(key, val, ((val / guestlogin_total) * 100)))
print()

print("SMBv1 support stats:")
print("\tTotal number of responses to SMBv1 nego packet:", smbv1_total)
for key, val in smbv1support_cnt.items():
    print(f"\t{key}: {val} ({val / smbv1_total * 100:.2f}%)")
print()

print("SMBv3 support stats:")
print("\tTotal number of responses to SMBv3 nego packet:", smbv3_total)
for key, val in smbv3support_cnt.items():
    print(f"\t{key}: {val} ({val / smbv3_total * 100:.2f}%)")
print()
    
print("Classification stats:")
print("\tTotal number of responses to classification packet:", classifications_total)
print(f"\tPremature session exit: {perc_stats['Premature session exit'][0]} {perc_stats['Premature session exit'][0] / classifications_total * 100:.2f}%")
print("\tDuplicate 100% categorizations:", dup_100)
print("\tDuplicate categorizations:", dup_class)
print()

for key, stats in sorted(list(perc_stats.items())[1:], key=lambda x: x[1][0], reverse=True):
    print("{}: {:.2f}% ({})". format(key, ((stats[0] / classifications_total) * 100), stats[0]))
    for subkey, cnt in sorted(stats[1].items(), key=lambda x: x[0], reverse=True):
        print(f"\t{subkey * 100:.2f}%: {cnt} ({cnt / stats[0] * 100:.2f}%)")