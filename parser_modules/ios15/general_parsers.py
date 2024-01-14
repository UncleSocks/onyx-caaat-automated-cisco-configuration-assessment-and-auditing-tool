from ssh_module import ssh_send
from report import generate_report


def compliance_check_with_expected_output(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if command_output:
        compliant = True
    else:
        compliant = False
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_with_expected_empty_output(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if not command_output or command_output.split(" ")[0].lower() == "no":
        compliant = True
    else:
        compliant = False
    current_configuration = None if not command_output else command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_without_no_prefix(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if command_output.split(" ")[0].lower() == "no":
        compliant = False
    else:
        compliant = True
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
