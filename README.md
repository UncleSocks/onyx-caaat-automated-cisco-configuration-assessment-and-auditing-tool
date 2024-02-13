![onyx](https://github.com/UncleSocks/onyx-caaat-cis-cisco-ios-assessment/assets/79778613/00acbed4-5b01-4c06-bfe5-963b53cd6559)

# ONYX: Cisco Automated Assessment and Auditing Tool (CAAAT)

![Static Badge](https://img.shields.io/badge/License-MIT-yellow) ![Static Badge](https://img.shields.io/badge/Release-2024.1.0-green)


ONYX: CAAAT is a Python3 tool, named after our rescued black cat, that performs automated Center for Internet Security (CIS) Cisco IOS 15 and 17 Benchmark assessments. It is built by Tyrone Kevin Ilisan for his Master's degree capstone project.

## Software Architecture

ONYX comprises of multiple Python scripts and modules:

![architecture](https://github.com/UncleSocks/onyx-caaat-automated-cisco-ios-configuration-assessment-and-auditing-tool/assets/79778613/cba5a070-133e-4be9-a2a6-322ec3695982)


## Prerequisites

Run `pip install -r requirements.txt` to install the tool's dependencies.

### Dependencies

The tool uses `Netmiko` to connect to the target Cisco IOS router via SSH. The `Maskpass` and `PrettyTable` are used to obfuscate the login password and display the report output in the CLI, respectively.

**Note:** SSH must already be configured on the target Cisco IOS router and the host machine, running the tool, should also have a stable connection to the router.

## Options
`-v` or `--version`: Explicitly specify the target's Cisco IOS version, either 15 or 17. If this option is not specified, the tool will attempt to identify the router's version automatically. 

`-o` or `--output`: Specify the HTML report filename with the `.html` extension. If this option is not specified, the tool will not export the report in HTML format and will only display the output in the CLI.

## Usage
**Quick Start**: Simply run `onyx.py` and wait for ONYX to complete its assessment.

**Start with Options**: Run `onyx.py -v [15|17] -o <filename>.html` to explicitly specify the Cisco IOS version and export the output in HTML format.

**Example:** 

```
C:\Users\UncleSocks\Documents\Tools\Onyx_Directory\onyx.py -v 17 -o report.html
```

### Running ONYX: CAAAT
When running ONYX, it will require you to enter the Cisco router's **IP address**, **username**, **password**, and **enable password/secret**. Ensure that the target is reachable. 

```
==================================================================================================================================
==================================================================================================================================
                                        :;       ..    _______
                                          +X$XxxX$x    < MEOW >
                                          X$$$XXX+    [_______]
                                          :$$X$xX$:   /
                                      .;$X$$$X$$$
                                    :X$$X$$$$XXx;+
                                  :XX$$$$$$$$$&$XX
                                .XXX$$$$$XXX$&&$.
                                xXXX$$$$$XX$&$;   +$&+ &&X.  .;&&&&&+  ;&&;.$&&&&&.  ;&$. :&&&&&x. ;&$:
                                x$$X$$$&$X$$$+  :&&&&. $&&&X   x$&&&&X  ..   X&&&&$   :    .&&&&&+ :;
                                ;$$$$$$$$$$$$   &&&&&. $&&&&x  x +&&&&&..     X&&&&$::      .&&&&&x
                                .$$$$$$$$$$$X  .&&&&&. $&&&&X  x  .&&&&&X      x&&&&+        .&&&&&;
                                .X$$$$$$$$$$x   $&&&&. $&&&&.  x    $&&&&      ;&&&&+       :.:&&&&&:
                                ;$$$$$$$$$$$$$$.  +&&&. $&&&.  .&.    +&&&      ;&&&&+      $:  .&&&&&:
                                ;$$X.   ....XX:     ......     ..    ....      ......      ..  .......  , iii, iv, v
                                  X$$$Xxxx+xX
                                      .:;x;           Cisco Automated Assessment and Auditing Tool


Created by Tyrone Kevin Ilisan (@unclesocks)

[+] Release 2024.1.0
[+] Audits CIS Cisco IOS 15 and IOS 17 Benchmarks version 8
[+] Supports HTML and CLI output

Tip: Use the -h option for more information on how to use Onyx's arguments and ensure stable connectivity between
the target Cisco router and the host machine running the CAAAT.

GitHub: https[://]github[.]com/UncleSocks/onyx-caaat

==================================================================================================================================

Target > 192.168.157.251
Username > admin
Password > ********
Enable # ********

Connecting to target Cisco router 192.168.157.251 via SSH...
Identifying Ciso IOS version.
Cisco IOS Version: 17
Running CIS Ciso IOS 17 Benchmark assessment.

Performing CIS Cisco IOS 17 Management Plane Benchmarks assessment.
Performing CIS Cisco IOS 17 Control Plane Benchmarks assessment.
Performing CIS Cisco IOS 17 Data Plane Benchmarks assessment.
Generating assessment report.
```
Once SSH connection is established, it will identify the Cisco IOS version and run the CIS checks on the three planes (Management, Control, and Data). Wait until the tool has completed its CIS checks and it will automatically generate a report for you.

## Assessment Output

ONYX is capable of displaying its assessments reports in CLI and HTML format.

### CLI Assessment Report

The report is divided into two main sections: the **Report Summary** and the **Assessment Breakdown**. 

The Report Summary displays the overall number of **Passed**, **Failed**, and **Not Applicable (NA)** compliance checks. It also displays a high-level table of the different CIS checks performed and their compliance result.

**Note:** The NA checks typically comprises of services/configuration that are not enabled.

```
============================================================================================================================================

                                                 -- CIS CISCO IOS BENCHMARK ASSESSMENT REPORT --
--------------------------------------------------------------------------------------------------------------------------------------------

                                                                REPORT SUMMARY
                                                ------------------------------------------------

Target: 192.168.157.251
Version: 17

+ Passed Compliance Checks: 39
+ Failed Compliance Checks: 45
+ Unchecked Compliance Checks: 11

Compliance Score Breakdown

+ Management Plane: 12 Passed; 21 Failed; 9 Unchecked
+ Control Plane: 11 Passed; 19 Failed; 0 Unchecked
+ Data Plane: 16 Passed; 5 Failed; 2 Unchecked



                                                MANAGEMENT PLANE
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
| CIS Check                                                                                                            | Level |   Compliant    |
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
| 1.1.1 Enable 'aaa new-model'                                                                                         |   1   |     False      |
| 1.1.2 Enable 'aaa authentication login'                                                                              |   1   |     False      |
| 1.1.3 Enable 'aaa authentication enable default'                                                                     |   1   |     False      |
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
--Truncated Result--

 						CONTROL PLANE
+----------------------------------------------------------------------------------------------------------------------+-------+-----------+
| CIS Check                                                                                                            | Level | Compliant |
+----------------------------------------------------------------------------------------------------------------------+-------+-----------+
| 2.1.1.1.1 Set the 'hostname'                                                                                         |   1   |    True   |
| 2.1.1.1.2 Set the 'ip domain-name'                                                                                   |   1   |    True   |
| 2.1.1.1.3 Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'                               |   1   |    True   |
+----------------------------------------------------------------------------------------------------------------------+-------+-----------+
--Truncated Result--

 						DATA PLANE
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
| CIS Check                                                                                                            | Level |   Compliant    |
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
| 3.1.1 Set 'no ip source-route'                                                                                       |   1   |     False      |
| 3.1.2 Set 'no ip proxy-arp'                                                                                          |   2   |     False      |
| 3.1.3 Set 'no interface tunnel;                                                                                      |   2   |      True      |
+----------------------------------------------------------------------------------------------------------------------+-------+----------------+
--Truncated Result--
```

The **Assessment Breakdown** provides a more detailed output of each of the CIS checks, including the current configuration of the Cisco router. A sample output is displayed below.
```
3.3.3 Require RIPv2 Authentication if Protocol is Used

+------------------------------------------+-------+-----------+---------------------------------------------------------------------------+
| CIS Check                                | Level | Compliant | Current Configuration                                                     |
+------------------------------------------+-------+-----------+---------------------------------------------------------------------------+
| 3.3.3.1 Set 'key chain'                  |   2   |    True   | [{'Key Chain': 'MYCHAIN', 'Key': '1', 'Key String':                       |
|                                          |       |           | 'dlsu_secure_traffic'}, {'Key Chain': 'RIPCHAIN', 'Key': '2', 'Key        |
|                                          |       |           | String': 'secure_rip'}]                                                   |
| 3.3.3.2 Set 'key'                        |   2   |    True   | [{'Key Chain': 'MYCHAIN', 'Key': '1', 'Key String':                       |
|                                          |       |           | 'dlsu_secure_traffic'}, {'Key Chain': 'RIPCHAIN', 'Key': '2', 'Key        |
|                                          |       |           | String': 'secure_rip'}]                                                   |
+------------------------------------------+-------+-----------+---------------------------------------------------------------------------+
```

### HTML Assessment Report
When the `-o` or `--output` option is specified, the tool will output an HTML report. 

**Note:** The HTML reports are stored under the `reports_module/reports` folder. 

![image](https://github.com/UncleSocks/onyx-caaat-cis-cisco-ios-assessment/assets/79778613/83977183-c97e-44a3-87a4-68fa0996cf05)

Two sample HTML reports are provided for reference; `sample_ios15` for Cisco IOS 15 and `sample_ios17` for Cisco IOS 17. 
