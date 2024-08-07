import re
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


def compliance_check_with_expected_empty_output(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if not command_output:
        compliant = True

    elif command_output.split(" ")[0].lower() == "no":
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


def compliance_check_banner(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    banner_search = re.search(r'^.*?\^C(?P<banner>.*?)\^C', command_output, re.MULTILINE | re.DOTALL)

    compliant = bool(banner_search)
    current_configuration = banner_search.group('banner') if banner_search else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))