![onyx](https://github.com/UncleSocks/onyx-caaat-cis-cisco-ios-assessment/assets/79778613/00acbed4-5b01-4c06-bfe5-963b53cd6559)

# ONYX: Cisco Another Automated Assessment Tool (CAAAT)

![Static Badge](https://img.shields.io/badge/License-MIT-yellow) ![Static Badge](https://img.shields.io/badge/Release-2024.1.0-green)


ONYX: CAAAT is a Python3 tool, named after our rescued black cat, that performs automated Center for Internet Security (CIS) Cisco IOS 15 and 17 Benchmark assessments. It is built by Tyrone Kevin Ilisan for his Master's degree capstone project.

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

**Example:** `onyx.py -v 15 -o report.html`

**Note**: The HTML reports are located under the `./report_modules/reports/` folder. A `sample.html` file is provided as a reference.

