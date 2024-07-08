import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_hostname(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.match(r'hostname (?P<hostname>\S+)', command_output)
    if regex_pattern:
        hostname = regex_pattern.group('hostname')
    else:
        raise ValueError("Error P0001 - Hostname Parser did not match any value.")
        
    compliant = hostname.lower() != "router"
    current_configuration = command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_domain_name(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    domain_name_search = re.search(r'ip\s+(?:domain\s+name|domain-name)\s+(?P<domain_name>\S+)(?=\n|$)', command_output, re.DOTALL)

    if domain_name_search:
        domain_name = domain_name_search.group('domain_name')

    else:
        domain_name = None

    compliant = bool(domain_name_search)
    current_configuration = f"Domain Name: {domain_name}"
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_ssh(connection, command, cis_check_one, cis_check_two, cis_check_three, level, global_report_output):
    command_output = ssh_send(connection, command)
    ssh_info_pattern = re.search(r'SSH (?P<status>Enabled|Disabled) - version (?P<version>\d+\.\d+)', command_output)

    if ssh_info_pattern:
        ssh_status = ssh_info_pattern.group('status')
        ssh_version =ssh_info_pattern.group('version')

    auth_timeout_pattern = re.search(r'Authentication timeout: (?P<timeout>\d+) secs', command_output)
    if auth_timeout_pattern:
        auth_timeout = int(auth_timeout_pattern.group('timeout'))

    auth_retries_pattern =  re.search(r'Authentication retries: (?P<retries>\d+)', command_output)
    if auth_retries_pattern:
        auth_retries = int(auth_retries_pattern.group('retries'))

    ssh_info = {'Status':ssh_status, 'Version':ssh_version, 'Authentication Timeout':auth_timeout, 'Authentication Retries':auth_retries}    
    return compliance_check_ssh_config(ssh_info, cis_check_one, cis_check_two, cis_check_three, level, global_report_output)
    

def compliance_check_ssh_config(ssh_info, cis_check_one, cis_check_two, cis_check_three, level, global_report_output):

    compliant = ssh_info["Authentication Timeout"] <= 60
    current_configuration = f"Authentication Timeout: {ssh_info['Authentication Timeout']} secs"
    global_report_output.append(generate_report(cis_check_one, level, compliant, current_configuration))

    compliant = ssh_info["Authentication Retries"] <= 3
    current_configuration = f"Authentication Retries: {ssh_info['Authentication Retries']}"
    global_report_output.append(generate_report(cis_check_two, level, compliant, current_configuration))

    compliant = ssh_info["Version"] == "2.0"
    current_configuration = ssh_info
    global_report_output.append(generate_report(cis_check_three, level, compliant, current_configuration))