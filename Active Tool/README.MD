CODESYS Version Extractor
=========

CODESYS stands for controller development system. It’s a development environment for programming controller applications in line with the IEC 61131-3 standard. It was developed and is still maintained by the 3S (Smart Software Solutions) Company in Germany. The platform-independent development environment is compatible with approximately 1,000 different device types from over 500 manufacturers and several million devices.

Our product aimed at extracting the CODESYS version via bunch of different ways.
In light of recent events (which includes numerous CODESYS vulnerabilities) we would like to present a tool which will extract CODESYS version and allow different SOCs and IT admins to take counter measures and protect their organisation form malicious attacks.   
 
 
## Getting Started
 
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
```
git clone https://github.com/microsoft/CoDe16.git
```

### Prerequisites

- Install Python >= 3.9: https://www.python.org/downloads

### Installing

- Install python requirements

    ``` 
    pip install -r requirements.txt
   ```
  
  
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
  --dst_ip DST_IP      The IP address of the remote plc.
  --src_ip SRC_IP      The IP address of the machine that will run this
                       script.

```

### General application arguments:
|          Args          |                             Description                             | Required / Optional |
|:----------------------:|:-------------------------------------------------------------------:|:-------------------:|
|     `-h`, `--help`     |                   show this help message and exit                   |      Optional       |
| `--dst_ip`             |              The IP address of the remote PLC                       |      Required       |
| `--src_ip`             |The local IP address of the machine that run this script             |      Required       |
|    `--username`        |Username to connected with to the PLC, required to run PLCShell command|      Optional       |
|  `--password`          |Password to connected with to the PLC, required to run PLCShell command|      Optional       |

## Explanation of the methods

### Name Service Resolution 
Using the Name Service of CODESYS to extract information on the PLC, including firmware version, vendor, device name and more.
No username and password required


### PLC Shell Service
The CODESYS PLCShell services allows query for different information from CODESYS device.
more information can be found at: 
[Codesys PLC Shell Service Doc](https://help.codesys.com/api-content/2/codesys/3.5.14.0/en/_cds_edt_device_plc_shell/)

Required username and password, but it is not present on every CODESYS systems.
We are using this service via ``rtsinfo`` command that returns the current CODESYS version.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

## Legal Disclaimer

Copyright (c) 2018 Microsoft Corporation. All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

