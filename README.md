# CoDe16
## Intro
Microsoft cyber-physical system (CPS) researchers recently identified 15 high severity vulnerabilities in the CODESYS V3 software development kit (SDK), a software development environment widely used to program and engineer programmable logic controllers (PLCs). Exploiting the discovered vulnerabilities, which affect all versions of CODESYS V3 prior to version 3.5.19.0, could put operational technology (OT) infrastructure at risk of attacks, such as remote code execution (RCE) and denial of service (DoS). The discovery of these vulnerabilities highlights the critical importance of ensuring the security of industrial control systems and underscores the need for continuous monitoring and protection of these environments.

CODESYS is compatible with approximately 1,000 different device types from over 500 manufacturers and several million devices who that use the solution to implement the international industrial standard IEC 611131-3. A DoS attack against a device using a vulnerable version of CODESYS could enable threat actors to shut down a power plant, while remote code execution could create a backdoor for devices and let attackers tamper with operations, cause a PLC to run in an unusual way, or steal critical information. Nonetheless, exploiting the discovered vulnerabilities requires user authentication, as well as deep knowledge of the proprietary protocol of CODESYS V3 and the structure of the different services that the protocol uses.

Microsoft researchers reported the discovery to CODESYS in September 2022, and worked closely with CODESYS to ensure that the vulnerabilities are patched. Information on the patch released by CODESYS to address these vulnerabilities can be found here [CODESYS Development System V3 | CODESYS Store International](https://store.codesys.com/engineering/codesys.html?___store=en). We strongly urge CODESYS users to apply these security updates as soon as possible. We also thank CODESYS for their collaboration and recognizing the urgency in addressing these vulnerabilities. 

Below is the list of all discovered vulnerabilities: 

| CVE | CODESYS component | Impact |
| --- | --- | --- |
| [CVE-2022-47379](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47379) | CMPapp | DoS, RCE  |
| [CVE-2022-47380](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47380) | CMPapp | DoS, RCE  |
| [CVE-2022-47381](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47381) | CMPapp | DoS, RCE  |
| [CVE-2022-47382](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47382) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47383](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47383) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47384](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47384) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47385](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47385) | CmpAppForce | DoS, RCE  |
| [CVE-2022-47386](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47386) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47387](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47387) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47388](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47388) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47389](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47389) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47390](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47390) | CmpTraceMgr | DoS, RCE  |
| [CVE-2022-47391](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47391) | CMPDevice | DoS  |
| [CVE-2022-47392](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47392) | CmpApp/ CmpAppBP/ CmpAppForce | DoS  |
| [CVE-2022-47393](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-47393) | CmpFiletransfer | DoS  |


Out of the 15 vulnerabilities, 14 have a CVSS score of 8.8, and CVE-2022-47391 has a score of 7.5.   

## What this repo contains?
* [Full white paper of the research](/white_paper.pdf)
* [Active tool to extract the CODESYS V3 runtime version of devices](/Active%20Tool/)
* [Wireshark Dissectorfor CODESYS V3 proprietary protocol](/Wireshark%20Dissector/)
* [IDA Python scripts that we wrote during our research](/IDA%20Python%20script/)
* [Demo Videos](/Demo%20Videos/)

## Researchers
* **Vladimir Tokarev, Microsoft Threat Intelligence Community**


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
