from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_with_expected_output(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if command_output:
        compliant = True
    else:
        compliant = False
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))