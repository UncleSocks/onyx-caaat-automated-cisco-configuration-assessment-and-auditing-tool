import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def complaince_check_snmp_enabled(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "snmp agent not enabled" in command_output.lower()
    current_configuration = "snmp agent enabled" if not compliant else command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    return compliant


def compliance_check_no_snmp(global_report_output):
    snmp_cis_checks = [{'CIS Check':"1.5.2 Unset 'private' for 'snmp-server community'", 'Level':1}, {'CIS Check':"1.5.3 Unset 'public' for 'snmp-server community'", 'Level':1}, 
                     {'CIS Check':"1.5.4 Do not set 'RW' for any 'snmp-server community'", 'Level':1}, {'CIS Check':"1.5.5 Set the ACL for each 'snmp-server community'", 'Level':1}, 
                     {'CIS Check':"1.5.6 Create an 'access-list' for use with SNMP", 'Level':1}, {'CIS Check':"1.5.7 Set 'snmp-server host' when using SNMP", 'Level':1}, 
                     {'CIS Check':"1.5.8 Set 'snmp-server enable traps snmp'", 'Level':1}, {'CIS Check':"1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3", 'Level':2}, 
                     {'CIS Check':"1.5.10 Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", 'Level':2}]
    
    for snmp_cis_check in snmp_cis_checks:
        compliant = "Not Applicable"
        current_configuration = "snmp agent not enabled"
        cis_check = snmp_cis_check['CIS Check']
        level = snmp_cis_check['Level']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_community(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if not command_output:
        compliant = True
        current_configuration = None
    else:
        compliant = False
        current_configuration = command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_rw(connection, command, cis_check_1, cis_check_2, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'snmp-server community (?P<string>\S+) (?P<access>\S+)(?: (?P<acl>\S+))?(\n|$)')
    parser = regex_pattern.finditer(command_output)
    snmp_community_list = []
    snmp_acl_list = []
    non_compliant_snmp_counter = 0

    for match in parser:
        community_string = match.group('string')
        access = match.group('access')
        acl = match.group('acl') or None
        current_snmp_info = {"String":community_string, "Access":access}
        snmp_community_list.append(current_snmp_info)
        if access.lower() == "rw":
            non_compliant_snmp_counter += 1
        
        current_snmp_acl = {"String":community_string, "ACL":acl}
        snmp_acl_list.append(current_snmp_acl)

    compliant = non_compliant_snmp_counter == 0
    current_configuration = snmp_community_list if snmp_community_list else None
    global_report_output.append(generate_report(cis_check_1, level, compliant, current_configuration))
    return compliance_check_snmp_acl(cis_check_2, snmp_acl_list, level, global_report_output)


def compliance_check_snmp_acl(cis_check, snmp_acl_list, level, global_report_output):
    non_compliant_snmp_counter = 0
    for snmp in snmp_acl_list:
        if snmp['ACL'] is None:
            non_compliant_snmp_counter += 1
    
    compliant = non_compliant_snmp_counter == 0
    current_configuration = snmp_acl_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_group(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'groupname:\s+(?P<group>\S+)\s+security model:(?P<model>.*?(?=\n|$))')
    parser = regex_pattern.findall(command_output)
    snmp_group_list = []

    for match in parser:
        groupname, security_model = match
        security_model_list = [model.strip() for model in security_model.split(",")]
        existing_snmp_check = next((snmp for snmp in snmp_group_list if snmp['Groupname'] == groupname), None)
        if existing_snmp_check is None:
            current_snmp_info = {"Groupname":groupname, "Security Models":security_model_list}
            snmp_group_list.append(current_snmp_info)            
        else:
            existing_snmp_check["Security Models"].extend(security_model_list)

    return compliance_check_snmp_priv(snmp_group_list, cis_check, level, global_report_output)


def compliance_check_snmp_priv(snmp_group_list, cis_check, level, global_report_output):
    non_compliant_snmp_group_counter = 0

    for snmp_group in snmp_group_list:
        if any("v3" in model for model in snmp_group["Security Models"]) and not any("priv" in model for model in snmp_group["Security Models"]):
            non_compliant_snmp_group_counter += 1
    
    compliant = non_compliant_snmp_group_counter == 0
    current_configuration = snmp_group_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_snmp_user(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'''User\ name:\s+(?P<username>\w+)\nEngine\ ID:\s+(?P<engine_id>[\w\d]+)\nstorage-type:\s+(?P<storage_type>\S+\s+\S+)
                               \nAuthentication\ Protocol:\s+(?P<auth_protocol>\w+)\nPrivacy\ Protocol:\s+(?P<privacy_protocol>\w+)
                               \nGroup-name:\s+(?P<groupname>\w+)\n''', re.VERBOSE)
    
    parser = regex_pattern.finditer(command_output)
    snmp_user_list = []
    non_compliant_snmp_user_counter = 0

    for match in parser:
        username = match.group('username')
        auth_protocol = match.group('auth_protocol')
        privacy_protocol = match.group('privacy_protocol')
        groupname = match.group('groupname')
        current_snmp_user_info = {"Username":username, "Authentication Protocol":auth_protocol,
                                  "Privacy Protocol":privacy_protocol, "Groupname":groupname}
        
        if privacy_protocol.lower() != "aes128":
            non_compliant_snmp_user_counter += 1

        snmp_user_list.append(current_snmp_user_info)
    
    compliant = non_compliant_snmp_user_counter == 0
    current_configuration = snmp_user_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
