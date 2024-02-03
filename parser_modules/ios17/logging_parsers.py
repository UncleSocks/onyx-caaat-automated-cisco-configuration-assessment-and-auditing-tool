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


def compliance_check_success_failure_log(connection, command, cis_check, level, global_report_output):
    logging_failure_success_commands = ["Failure", "Success"]
    
    logging_failure_success_list = []
    non_compliant_login_logging_counter = 0

    for logging_failure_success_command in logging_failure_success_commands:
        command_output = ssh_send(connection, f"{command}{logging_failure_success_command.lower()}")
        
        if not command_output:
            current_logging_failure_success_info = {f'Login {logging_failure_success_command} Logging':None}
            logging_failure_success_list.append(current_logging_failure_success_info)
            non_compliant_login_logging_counter += 1
        
        else:
            
            if command_output.split()[0].lower() == "no":
                current_logging_failure_success_info = {f'Login {logging_failure_success_command} Logging':command_output}
                logging_failure_success_list.append(current_logging_failure_success_info)
                non_compliant_login_logging_counter += 1
                
            else:
                current_logging_failure_success_info = {f'Login {logging_failure_success_command} Logging':command_output}
                logging_failure_success_list.append(current_logging_failure_success_info)
    
    compliant = non_compliant_login_logging_counter == 0
    current_configuration = logging_failure_success_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))