from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_cdp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "cdp is not enabled" in command_output.lower()
    current_configuration = command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))