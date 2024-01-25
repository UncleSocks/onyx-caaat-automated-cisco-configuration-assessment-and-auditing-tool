import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_logging_trap(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.search(r'Trap logging:\s+(?P<status>\w+)', command_output)

    if regex_pattern:
        trap_status = regex_pattern.group('status')

    else:
        raise ValueError("Error P0003 - Logging Trap Parser did not match any value.")
    compliant = trap_status == "Informational"
    current_configuration = command_output.strip()
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
