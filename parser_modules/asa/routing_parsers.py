import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_dynamic_routing_tester(connection, command):
    command_output = ssh_send(connection, command)

    regex_pattern = re.compile(r'^router\s+(?P<dynamic_route>ospf|eigrp|bgp)', re.MULTILINE)
    enabled_dynamic_routing_iter = regex_pattern.finditer(command_output)
    enabled_dynamic_routing = {'OSPF':False, 'EIGRP':False, 'BGP':False}

    if not enabled_dynamic_routing_iter:
        return enabled_dynamic_routing
    
    else:
        for enabled_dynamic_route in enabled_dynamic_routing_iter:
            dynamic_route = enabled_dynamic_route.group('dynamic_route').lower()

            if dynamic_route == "ospf":
                enabled_dynamic_routing['OSPF'] = True
            elif dynamic_route == "eigrp":
                enabled_dynamic_routing['EIGRP'] = True
            else:
                enabled_dynamic_routing['BGP'] = True

        return enabled_dynamic_routing
    

def compliance_check_no_enabled_dynamic_routing(global_report_output):
    dynamic_routing_cis_checks = [{'CIS Check':"2.1.1 Ensure 'OSPF authentication' is enabled", 'Level':2},
                                  {'CIS Check':"2.1.2 Ensure 'EIGP authentication' is enabled", 'Level':2},
                                  {'CIS Check':"2.1.3 Ensure 'BGP authentication' is enabled", 'Level':2}]
    
    for dynamic_routing_cis_check in dynamic_routing_cis_checks:
        cis_check = dynamic_routing_cis_check['CIS Check']
        compliant = "Not Applicable"

        if dynamic_routing_cis_check['CIS Check'] == "2.1.1 Ensure 'OSPF authentication' is enabled":
            current_configuration = "OSPF is not enabled."
        elif dynamic_routing_cis_check['CIS Check'] == "2.1.2 Ensure 'EIGP authentication' is enabled":
            current_configuration = "EIGP is not enabled."
        else:
            current_configuration = "BGP is not enabled."

        level = dynamic_routing_cis_check['Level']
        
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))