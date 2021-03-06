# Looking for Honey Once Again: Detecting RDP and SMB Honeypots on the Internet

This repository contains the tools we used to perform the internet scan for RDP and SMB honeypots. The results are described in our research paper "Looking for Honey Once Again: Detecting RDP and SMB Honeypots on the Internet" that will appear on the 7th International Workshop on Traffic Measurements for Cybersecurity (WTMC 2022).

## Dataset
We collected Pcaps and encrypted TLS traffic captures of all our experiments we conducted and would like to offer it to interested researchs. However, the dataset might contain information about hosts with security vulnerabilites which we would like to not put at risk. Therefore, we will offer our dataset only at request.

If you are interested in our dataset, please send a mail to franzen [AT] sec.in.tum.de.

## How to use our tools

Our scanners are supposed to be used with the ZMap internet scanner. Therefore, to perform a scan for RDP or SMB honeypots you can e.g. perform the follwoing command:

    zmap -p 3359 | python3 RDP_scan_asyncio.py

or

    zmap -p 445 | python3 SMB_scan_asyncio.py
