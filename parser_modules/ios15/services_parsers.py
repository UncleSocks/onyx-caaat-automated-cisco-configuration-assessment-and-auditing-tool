from ssh_module import ssh_send
from report import generate_report



def compliance_check_cdp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "cdp is not enabled" in command_output.lower()
    current_configuration = command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_bootp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "no ip bootp server" in command_output.lower()
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_service_pad(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "no service pad" in command_output.lower()
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))











    