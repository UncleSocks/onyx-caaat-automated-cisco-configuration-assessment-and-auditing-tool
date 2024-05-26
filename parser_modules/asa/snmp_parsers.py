import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_snmp_enabled(connection, command):
    command_output = ssh_send(connection, command)
    if command_output:
        return True
    else:
        return False
    

def compliance_check_disabled_snmp(global_report_output):
    snmp_cis_checks = [{'CIS Check':"1.11.1 Ensure 'snmp-server group' is set to 'v3 priv'", 'Level':1}, 
                       {'CIS Check':"1.11.2 Ensure 'snmp-server user' is set to 'v3 auth SHA'", 'Level':1},
                       {'CIS Check':"1.11.3 Ensure 'snmp-server host' is set to 'version 3'", 'Level':1},
                       {'CIS Check':"1.11.4 Ensure 'SNMP traps' is enabled", 'Level':1},
                       {'CIS Check':"1.11.5 Ensure 'SNMP community string' is not the default string", 'Level':1}]

    for snmp_cis_check in snmp_cis_checks:
        compliant = "Not Applicable"
        current_configuration = "SNMP not enabled or incomplete configuration"
        cis_check = snmp_cis_check['CIS Check']
        level = snmp_cis_check['Level']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_server_group(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    snmp_server_group_list = []
    non_compliant_server_group_counter = 0

    regex_pattern = re.compile(r'^snmp-server\s+group\s+(?P<group_name>\S+)\s+v3\s+(?P<security_model>\w+)', re.MULTILINE)
    snmp_server_group_match = regex_pattern.findall(command_output)

    if snmp_server_group_match:
        for snmp_server_group in snmp_server_group_match:
            group_name = snmp_server_group[0]
            security_model_type = snmp_server_group[1]

            if security_model_type != "priv":
                non_compliant_server_group_counter += 1

            current_snmp_server_group_info = {'Group Name':group_name, 'Security Model':security_model_type}
            snmp_server_group_list.append(current_snmp_server_group_info)

    current_configuration = snmp_server_group_list if snmp_server_group_list else None
    compliant = bool(snmp_server_group_list) and non_compliant_server_group_counter == 0
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_server_user(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    snmp_server_user_list = []
    non_compliant_snmp_server_user_counter = 0

    regex_pattern = re.compile(r'^snmp-server\s+user\s+(?P<username>\S+)\s+(?P<groupname>\S+)\s+v3\s+engineID\s+\S+\s+(?:encrypted\s+auth\s+(?:(?P<auth_type>\w+))\s+\S+\s+(?=\s*))?(?:priv\s+(?P<priv_type>(?:aes\s+\d+|3des))\s+\S+\s*(?=\s*))?$', re.MULTILINE)
    snmp_server_user_match = regex_pattern.findall(command_output)

    if snmp_server_user_match:
        for snmp_server_user in snmp_server_user_match:
            user_name = snmp_server_user[0]
            group_name = snmp_server_user[1]
            auth_type = snmp_server_user[2] if snmp_server_user[2] else None
            priv_type = snmp_server_user[3] if snmp_server_user[3] else None

            if priv_type == "3des" or priv_type == None or auth_type == None:
                non_compliant_snmp_server_user_counter += 1

            current_snmp_server_user_info = {'User Name':user_name, 'Group Name':group_name, 'Auth Type':auth_type, 'Priv Type':priv_type}
            snmp_server_user_list.append(current_snmp_server_user_info)

    current_configuration = snmp_server_user_list if snmp_server_user_list else None
    compliant = bool(snmp_server_user_list) and non_compliant_snmp_server_user_counter == 0
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_server_host(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    snmp_host_list = []
    non_compliant_snmp_host_counter = 0

    regex_pattern = re.compile(r'^snmp-server\s+host\s+(?P<interface>\S+)\s+(?P<ip_address>\S+)\s+(?:(?:community\s+(?P<string>(?:\d+\s+\S+)|\S+)\s+(?:version\s+(?P<version>\w+))?\s*(?:udp-port\s+(?P<port>\d+))?)|(?:version\s+(?P<version_v3>\d+)\s+(?P<user>\S+)\s*(?:udp-port\s+(?P<port_v3>\d+))?))', re.MULTILINE)
    snmp_server_host_iter = regex_pattern.finditer(command_output)

    for snmp_server_host in snmp_server_host_iter:
        interface = snmp_server_host.group('interface')
        ip_address = snmp_server_host.group('ip_address')
        community_string = snmp_server_host.group('string') if snmp_server_host.group('string') else "SNMPv3"
        version = snmp_server_host.group('version') or snmp_server_host.group('version_v3') if snmp_server_host.group('version') or snmp_server_host.group('version_v3') else "1"
        user = snmp_server_host.group('user') if snmp_server_host.group('user') else "Not applicable on SNMPv1/v2c"
        udp_port = snmp_server_host.group('port') if snmp_server_host.group('port') else "161" or snmp_server_host.group('port_v3') if snmp_server_host.group('port_v3') else "161"

        if version != "3":
            non_compliant_snmp_host_counter += 1
        
        current_snmp_host_info = {'Interface':interface, 'IP Address':ip_address, 'Community String':community_string,
                                  'SNMP Version':version, 'SNMP User':user, 'SNMP UDP Port':udp_port}
        
        snmp_host_list.append(current_snmp_host_info)

    current_configuration = snmp_host_list if snmp_host_list else None
    compliant = non_compliant_snmp_host_counter == 0
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_traps(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    if not command_output:
        compliant = False

    else:
        snmp_traps_output_split = command_output.split()

        if snmp_traps_output_split[0] == "no":
            compliant = False

        else:
            snmp_enabled_traps = snmp_traps_output_split[4:]

            if "authentication" in snmp_enabled_traps and "linkup" in snmp_enabled_traps and "linkdown" in snmp_enabled_traps and "coldstart" in snmp_enabled_traps:
                compliant = True

    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))