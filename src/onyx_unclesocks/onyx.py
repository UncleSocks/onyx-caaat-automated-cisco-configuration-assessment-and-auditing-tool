# ONYX Cisco CAAAT (Configuration Assessment and Auditing Tool)
# GitHub @unclesocks: https://github.com/UncleSocks
#
# MIT License
#
# Copyright (c) 2024 Tyrone Kevin Ilisan
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
# OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


from datetime import datetime
from ssh import ssh_login
from init import ios_version_check, cisco_type_check, arguments, argument_checks, user_input, target_parse
from audit_modules.audit_ios15 import run_cis_cisco_ios_15_assessment, parsed_output_ios15
from audit_modules.audit_ios17 import run_cis_cisco_ios_17_assessment, parsed_output_ios17
from audit_modules.audit_asa import run_cis_cisco_asa_assessment
from report_modules.score import score_compute
from report_modules.html_report import report_html_output
from report_modules.main_report import report_cli_output
from strings import logo


def onyx():

    argument_checks(arguments().version, arguments().output)
    logo()

    device_counter = 0 
    if arguments().interactive:
        connect = user_input()
        device_count = 1
    else:
        target, device_count = target_parse()

    while device_counter < device_count:
        current_device = device_counter + 1
        print(f"Assessing device {current_device} out of {device_count}")
        
        if not arguments().interactive:
            device_key = f"t{str(current_device)}"

        try:
            
            ip_address = connect['IP Address'] if arguments().interactive else target[device_key]['ip_address']
            username = connect['Username'] if arguments().interactive else target[device_key]['username']
            password = connect['Password'] if arguments().interactive else target[device_key]['password']
            enable = connect['Enable Password'] if arguments().interactive else target[device_key]['enable']

            print(f"\nConnecting to target Cisco router {ip_address} via SSH...")            
            connection = ssh_login(ip_address, username, password, enable)

        except:
            print("Error 0001 - Unable to login to the target router, check IP address, login credentials, and device key for non-interactive mode.")
            print("Exiting the Onyx: CAAAT.")
            exit()

        if arguments().interactive and arguments().type is None:
            print("Identifying Cisco type.")
            cisco_type = cisco_type_check(connection)
        
        elif not arguments().interactive and 'type' not in target.get(device_key, {}):
            print("Identifying Cisco type.")
            cisco_type = cisco_type_check(connection)            
        
        else:
            cisco_type = arguments().type if arguments().interactive else target[device_key]['type']
        

        if cisco_type == "ios":
            print(f"Cisco Device Type: {cisco_type}")

            report_filename = arguments().output if arguments().interactive else f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}-{device_key}.html"

            if arguments().interactive and arguments().version is None:
                print("Identifying Ciso IOS version.")
                ios_version = ios_version_check(connection)

            elif not arguments().interactive and 'version' not in target.get(device_key, {}):
                print("Identifying Ciso IOS version.")
                ios_version = ios_version_check(connection)

            else:
                ios_version = arguments().version if arguments().interactive else target[device_key]['version']

            if ios_version == 15:
                print(f"Ciso IOS Version: {ios_version}")
                print("Running CIS Ciso IOS 15 Benchmark assessment.\n")
                cis_ios_15_assessment = run_cis_cisco_ios_15_assessment(connection)
                parsed_cis_ios_15_assessment = parsed_output_ios15(cis_ios_15_assessment)

                print("Generating assessment report.\n")
                cis_ios_15_compliance_score = score_compute(parsed_cis_ios_15_assessment)

                if arguments().output is None and arguments().interactive:
                    report_cli_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, ip_address, ios_version)
                else:
                    report_cli_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, ip_address, ios_version)

                    print("Exporting to an HTML output.")
                    report_html_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, report_filename, 
                                       ip_address, ios_version)
            
            elif ios_version == 17:
                print(f"Cisco IOS Version: {ios_version}")
                print("Running CIS Ciso IOS 17 Benchmark assessment.\n")
                cis_ios_17_assessment = run_cis_cisco_ios_17_assessment(connection)
                parsed_cis_ios_17_assessment = parsed_output_ios17(cis_ios_17_assessment)
                
                print("Generating assessment report.\n")
                cis_ios_17_compliance_score = score_compute(parsed_cis_ios_17_assessment)

                if arguments().output is None and arguments().interactive:
                    report_cli_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, ip_address, ios_version)
                else:
                    report_cli_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, ip_address, ios_version)

                    print("Exporting to an HTML output.")
                    report_html_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, report_filename, 
                                       ip_address, ios_version)

            else:
                print("Error 0002 - Unable to identify Cisco IOS version. Use the '-v' option to specify the IOS version manually. In target.json, ensure that the 'version' value is an integer and supported by ONYX.")

        elif cisco_type == "asa":
            print("Cisco ASA support still under development.")
            cis_asa_assessment = run_cis_cisco_asa_assessment(connection)
            for cis_asa in cis_asa_assessment:
                print(cis_asa)
        
        else:
            print("Error 0003 - Unable to identify Cisco type. Use the '-t' option to specify the type manually. In target.json, ensure that the 'type' value is supported by ONYX.")

        print("\nClosing SSH connection.")
        connection.disconnect
        device_counter += 1

    print("Assessment complete.")


if __name__ == "__main__":
    onyx()