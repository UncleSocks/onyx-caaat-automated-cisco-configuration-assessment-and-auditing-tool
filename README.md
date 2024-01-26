![icon](https://github.com/UncleSocks/onyx-caaat/assets/79778613/50651130-797f-4e7d-b3f9-72ad903db40b)
**NOTE: IOS17 ASSESSMENT CHECKS ARE STILL UNDER DEVELOPMENT**
# ONYX: Cisco Another Automated Assessment Tool (CAAAT)

ONYX: CAAAT is a Python3 tool, named after our rescued black cat, that performs automated Center for Internet Security (CIS) Cisco IOS Benchmarks version 8 audits on Cisco routers.

The tool is capable of assessing Cisco IOS versions 15 and 17 routers using the `Netmiko` module against the CIS Cisco IOS 15 and Cisco IOS 17 Benchmarks, respectively.

ONYX is created by Tyrone Kevin Ilisan as part of his Master in Information Security program.

## Prerequisites

Run `pip install -r requirements.txt` to install the tool's dependencies.

The tool uses `Netmiko` to connect to the target Cisco IOS router via SSH. The `Maskpass` and `PrettyTable` are used to obfuscate the login password and display the report output in the CLI, respectively.

**Note:** SSH must already be configured on the target Cisco IOS router and the host machine, running the tool, should also have a stable connection to the router.

## Options
`-v` or `--version`: Explicitly specify the target's Cisco IOS version, either 15 or 17. If this option is not specified, the tool will attempt to identify the router's version automatically. 

`o` or `--output`: Specify the HTML report filename with the `.html` extension. If this option is not specified, the tool will not export the report in HTML format and will only display the output in the CLI.

## Usage
**Quick Start**: Simply run `onyx.py` and wait for ONYX to complete its assessment.

**Start with Options**: Run `onyx.py -v [15|17] -o <filename>.html` to explicitly specify the Cisco IOS version and export the output in HTML format.

**Note**: The HTML reports are located under the `./report_modules/reports/` folder. A `sample.html` file is provided as a reference.
