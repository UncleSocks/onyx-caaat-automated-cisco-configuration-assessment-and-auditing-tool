from ssh import ssh_login
from init import ios_version_check, cisco_type_check, arguments, argument_checks, user_input
from audit_modules.audit_ios15 import run_cis_cisco_ios_15_assessment, parsed_output_ios15
from audit_modules.audit_ios17 import run_cis_cisco_ios_17_assessment, parsed_output_ios17
from audit_modules.audit_asa import run_cis_cisco_asa_assessment
from report_modules.score import score_compute
from report_modules.html_report import report_html_output
from report_modules.main_report import report_cli_output


def onyx():

    argument_checks(arguments().version, arguments().output)
    connect = user_input()

    try:
        print(f"\nConnecting to target Cisco router {connect['IP Address']} via SSH...")
        connection = ssh_login(connect['IP Address'], connect['Username'], 
                               connect['Password'], connect['Enable Password'])
    except:
        print("Error 0001 - Unable to login to the target router, check IP address, login credentials, and connectivity.")
        print("Exiting the Onyx: CAAAT.")
        exit()

    if arguments().type is None:
        print("Identifying Cisco type.")
        cisco_type = cisco_type_check(connection)
    else:
        cisco_type = arguments().type
    

    if cisco_type == "ios":
        if arguments().version is None:
            print("Identifying Ciso IOS version.")
            ios_version = ios_version_check(connection)
        else:
            ios_version = arguments().version

        if ios_version == 15:
            print(f"Ciso IOS Version: {ios_version}")
            print("Running CIS Ciso IOS 15 Benchmark assessment.\n")
            cis_ios_15_assessment = run_cis_cisco_ios_15_assessment(connection)
            parsed_cis_ios_15_assessment = parsed_output_ios15(cis_ios_15_assessment)

            print("Generating assessment report.\n")
            cis_ios_15_compliance_score = score_compute(parsed_cis_ios_15_assessment)

            if arguments().output is None:
                report_cli_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, connect['IP Address'], ios_version)
            else:
                report_cli_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, connect['IP Address'], ios_version)

                print("Exporting to an HTML output.")
                report_html_output(parsed_cis_ios_15_assessment, cis_ios_15_compliance_score, arguments().output, connect['IP Address'], ios_version)
        
        elif ios_version == 17:
            print(f"Cisco IOS Version: {ios_version}")
            print("Running CIS Ciso IOS 17 Benchmark assessment.\n")
            cis_ios_17_assessment = run_cis_cisco_ios_17_assessment(connection)
            parsed_cis_ios_17_assessment = parsed_output_ios17(cis_ios_17_assessment)
            
            print("Generating assessment report.\n")
            cis_ios_17_compliance_score = score_compute(parsed_cis_ios_17_assessment)

            if arguments().output is None:
                report_cli_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, connect['IP Address'], ios_version)
            else:
                report_cli_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, connect['IP Address'], ios_version)

                print("Exporting to an HTML output.")
                report_html_output(parsed_cis_ios_17_assessment, cis_ios_17_compliance_score, arguments().output, connect['IP Address'], ios_version)

        else:
            print("Error 0002 - Unable to identify Cisco IOS version. Use the '-v' option to specify the IOS version manually.")

    elif cisco_type == "asa":
        print("Cisco ASA support still under development.")
        cis_asa_assessment = run_cis_cisco_asa_assessment(connection)
        print(cis_asa_assessment)
    
    else:
        print("Error 0002 - Unable to identify Cisco type. Use the '-t' option to specify the type manually.")

    print("\nClosing SSH connection.")
    connection.disconnect


if __name__ == "__main__":
    onyx()