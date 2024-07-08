import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_logging_trap(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.search(r'Trap logging:\s*(?:level\s+)?(?P<status>emergencies|alerts|critical|errors|warnings|notifications|informational|debugging)', command_output, re.IGNORECASE)

    if regex_pattern:
        trap_status = regex_pattern.group('status')

    else:
        raise ValueError("Error P0003 - Logging Trap Parser did not match any value.")
    compliant = trap_status.lower() == "informational" or trap_status.lower() == "debugging"
    current_configuration = {'Trap Logging Level':trap_status}
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
