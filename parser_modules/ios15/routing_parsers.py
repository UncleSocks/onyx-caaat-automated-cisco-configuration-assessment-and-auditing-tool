import re
from ssh_module import ssh_send
from report import generate_report


def compliance_check_source_route(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "no ip source-route" in command_output.lower()
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_proxy_arp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'^(?P<interface>\S+).*?\n(?: {2}(?!Local).*\n)* {2}Proxy ARP is (?P<proxy_arp>enabled|disabled)\s*$', re.MULTILINE)
    parser = regex_pattern.finditer(command_output)
    non_compliant_interface_counter = 0
    interface_list = []

    for match in parser:
        interface = match.group('interface')
        proxy_arp = match.group('proxy_arp')
        if proxy_arp == "enabled":
            non_compliant_interface_counter += 1
        current_interface_info = {'Interface':interface, 'Proxy ARP':proxy_arp}
        interface_list.append(current_interface_info)
    
    compliant = non_compliant_interface_counter == 0
    current_configuration = interface_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
        

def compliance_check_urpf(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'^(?P<interface>\S+).*?IP verify source reachable-via RX', re.MULTILINE | re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    interface_list = []

    if not parser:
        compliant = False
    else:
        for match in parser:
            interface = match.group('interface')
            interface_list.append(interface)
        compliant = True
    
    current_configuration = interface_list if interface_list else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    

def compliance_check_dynamic_routing_tester(connection, command):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'router (?P<dynamic_route>eigrp|ospf|rip|bgp)', re.MULTILINE)
    parser = regex_pattern.finditer(command_output)
    enabled_dynamic_routing = {'EIGRP':False, 'OSPF':False, 'RIP': False, 'BGP': False}

    if not parser:
        return enabled_dynamic_routing
    else:

        for match in parser:
            dynamic_route = match.group('dynamic_route').lower()
            if dynamic_route == "eigrp":
                enabled_dynamic_routing['EIGRP'] = True
            elif dynamic_route == "ospf":
                enabled_dynamic_routing['OSPF'] = True
            elif dynamic_route == "rip":
                enabled_dynamic_routing['RIP'] = True
            elif dynamic_route == 'bgp':
                enabled_dynamic_routing['BGP'] = True

        return enabled_dynamic_routing
    