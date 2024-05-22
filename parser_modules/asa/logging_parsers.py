import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_logging_monitor(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    logging_monitor_match = re.match(r'logging\s+monitor\s+(?P<level>\w+)(?=\n|$)', command_output)

    if logging_monitor_match:
        logging_level = logging_monitor_match.group('level')
        current_configuration = {'Logging Monitor':"Enabled", 'Logging Level':logging_level}
    
    else:
        current_configuration = {'Logging Monitor':"Disabled", 'Logging Level':None}
    
    compliant = not bool(logging_monitor_match)
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_syslog_hosts(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    syslog_host_list = []

    regex_pattern = re.compile(r'^logging\s+host\s+(?P<interface>\S+)\s+(?P<address>\S+)', re.MULTILINE | re.DOTALL)
    syslog_hosts_match = regex_pattern.findall(command_output)

    if syslog_hosts_match:
        for syslog_host in syslog_hosts_match:
            host_interface = syslog_host[0]
            host_address = syslog_host[1]

            current_syslog_host_info = {'Syslog Interface':host_interface, 'Syslog Address':host_address}
            syslog_host_list.append(current_syslog_host_info)

    current_configuration = syslog_host_list if syslog_host_list else None
    compliant = bool(syslog_hosts_match)
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_logging_history(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    logging_history_level = None
    logging_history_match = re.match(r'logging\s+history\s+(?P<level>\w+)', command_output)

    if logging_history_match:
        logging_history_level = logging_history_match.group('level')    
    
    current_configuration = {'Logging History Level':logging_history_level}
    compliant = logging_history_level == "notifications" or logging_history_level == "informational" or logging_history_level == "debugging"
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))