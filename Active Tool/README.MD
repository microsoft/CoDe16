Codesys Version Extractor
=========

CoDeSyS stands for controller development system. It’s a development environment for programming controller applications in line with the IEC 61131-3 standard. It was developed and is still maintained by the 3S (Smart Software Solutions) Company in Germany. The platform-independent development environment is compatible with the PLCs and automation components of over 250 companies.

Our product aimed at extracting the codesys version via bunch of different ways.
In light of recent events (which includes numerous codesys vulnerabilities) we would like to present a tool which will extract Codesys version and allow different SOCs and IT admins to take counter measures and protect their organisation form malicious attacks.   
 
## Usage 

This project runs on python3.9.
```commandline
python3.9 main.py -h 
```
This will display basic manual the explains the usage of the tool:
```commandline
usage: main.py [-h] [--username USERNAME] [--password PASSWORD] --dst_ip
               DST_IP --src_ip SRC_IP

Welcome to RTS Version extractor.

optional arguments:
  -h, --help           show this help message and exit
  --username USERNAME  The username that required to log into the plc.
  --password PASSWORD  The password that required to log into the plc.
  --dst_ip DST_IP      The ip address of the remote plc.
  --src_ip SRC_IP      R|The address of the machine that will run this script.
                       (NOTE: should be in same subnet as the PLC)

```

## Types explained:

### PLC Shell Service
The codesys plc shell services allows query for different information from codesys device.
more information can be found at: 
[Codesys PLC Shell Service Doc](https://help.codesys.com/api-content/2/codesys/3.5.14.0/en/_cds_edt_device_plc_shell/)

The main issue is that this component is not always present in codesys systems.
We are using this service via ``rtsinfo`` command that returns the current Codesys version.


### PLC Files Management Service (by log path)
This feature is basically the same as last one but instead of using known location we give the user the ability to
provide the location of the log on the target machine.

### Name Service Resolution 
Return information on the PLC, including Firmware version, vendor and more

Tribute to LOTR, and mainly target for someone who's not sure what going on with his PLC 
which will run all the logics one after another until one will return an answer.

One Ring inscription.png

# Contributing 
This project is created for empowering each organization (and mainly keeping safe)
so one is welcome to contribute. 