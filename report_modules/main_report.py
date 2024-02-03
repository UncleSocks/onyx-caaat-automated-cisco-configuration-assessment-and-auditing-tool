from prettytable import PrettyTable


def generate_report(cis_check, level, compliant, current_configuration):
    current_check = {'CIS Check':cis_check, 'Level':level, 'Compliant':compliant, 'Current Configuration':current_configuration}
    return current_check


def configuration_tab_replace(current_configuration):
    if isinstance(current_configuration, str):
        return current_configuration.replace('\t', '')
    else:
        return current_configuration


def report_cli_output(parsed_report_output, compliance_score_dict, target_ip_address, ios_version):

    report_summary = f"""

============================================================================================================================================    
                                                                                                                
                                                 -- CIS CISCO IOS BENCHMARK ASSESSMENT REPORT -- 
--------------------------------------------------------------------------------------------------------------------------------------------

                                                                REPORT SUMMARY
                                                ------------------------------------------------

Target: {target_ip_address}
Version: {ios_version}                                                

+ Passed Compliance Checks: {compliance_score_dict['Total Passed Checks']}
+ Failed Compliance Checks: {compliance_score_dict['Total Failed Checks']}
+ Unchecked Compliance Checks: {compliance_score_dict['Total NA Checks']}

Compliance Score Breakdown

+ Management Plane: {compliance_score_dict['Passed Management Plane Checks']} Passed; {compliance_score_dict['Failed Management Plane Checks']} Failed; {compliance_score_dict['NA Management Plane Checks']} Unchecked
+ Control Plane: {compliance_score_dict['Passed Control Plane Checks']} Passed; {compliance_score_dict['Failed Control Plane Checks']} Failed; {compliance_score_dict['NA Control Plane Checks']} Unchecked
+ Data Plane: {compliance_score_dict['Passed Data Plane Checks']} Passed; {compliance_score_dict['Failed Data Plane Checks']} Failed; {compliance_score_dict['NA Data Plane Checks']} Unchecked


    """
    table = PrettyTable()
    table.field_names = ['CIS Check', 'Level', 'Compliant']
    table.align['CIS Check'] = 'l'
    table.align['Level'] = 'c'
    table.align['Compliant'] = 'c'
    table._min_width = {'CIS Check':116}
    table._max_width = {'CIS Check':116}

    for check in parsed_report_output['Management Plane Checks']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])
    
    report_summary += f"""
                                                MANAGEMENT PLANE
{table}
    """
    table.clear_rows()
    for check in parsed_report_output['Control Plane Checks']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])    
    report_summary += f"""
                                                 CONTROL PLANE
{table}
    """
    table.clear_rows()
    for check in parsed_report_output['Data Plane Checks']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])    
    report_summary += f"""
                                                  DATA PLANE
{table}

============================================================================================================================================
    """
    
    table = PrettyTable()
    table.field_names = ['CIS Check', 'Level', 'Compliant', 'Current Configuration']
    table.align['CIS Check'] = 'l'
    table.align['Level'] = 'c'
    table.align['Compliant'] = 'c'
    table.align['Current Configuration'] = 'l'
    table._min_width = {'CIS Check':40, 'Current Configuration':73}
    table._max_width = {'CIS Check':40, 'Current Configuration':73}


    report_body = f"""
                                                            ASSESSMENT BREAKDOWN
                                                ------------------------------------------------

============================================================================================================================================

                                                              MANAGEMENT PLANE


1.1 Local Authentication, Authorization and Accounting (AAA) Rules
"""
    for check in parsed_report_output['MP Local AAA Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

1.2 Access Rules    
"""
    table.clear_rows()
    for check in parsed_report_output['MP Access Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

1.3 Banner Rules    
    """
    table.clear_rows()
    for check in parsed_report_output['MP Banner Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

1.4 Password Rules    
    """
    table.clear_rows()
    for check in parsed_report_output['MP Password Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

1.5 SNMP Rules    
    """
    table.clear_rows()
    for check in parsed_report_output['MP SNMP Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}
    """
    if ios_version == 17:
        report_body += f"""
1.6 Login Enhancements    
        """
        table.clear_rows()
        for check in parsed_report_output['MP Login Enhancements']:
            table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
        report_body += f"""
{table}
        """
    report_body += f"""
--------------------------------------------------------------------------------------------------------------------------------------------


                                                                CONTROL PLANE

2.1 Global Service Rules
2.1.1 Setup SSH
2.1.1.1 Configure Prerequisites for the SSH Service    
"""
    table.clear_rows()
    for check in parsed_report_output['CP Global Services SSH Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}
    """

    table.clear_rows()
    for check in parsed_report_output['CP Global Services Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

2.2 Logging Rules    
    """
    table.clear_rows()
    for check in parsed_report_output['CP Logging Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

2.3 NTP Rules
2.3.1 Require Enryption Keys for NTP    
    """
    table.clear_rows()
    for check in parsed_report_output['CP NTP Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

2.4 Loopback Rules 
    """
    table.clear_rows()
    for check in parsed_report_output['CP Loopback Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

--------------------------------------------------------------------------------------------------------------------------------------------


                                                                    DATA PLANE

3.1 Routing Rules
    """
    table.clear_rows()
    for check in parsed_report_output['DP Routing Rules']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

3.2 Border Router Filtering
    """
    table.clear_rows()
    for check in parsed_report_output['DP Border Router Filtering']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

3.3 Neighbor Authentication

3.3.1 Require EIGRP Authentication if Protocol is Used
    """
    table.clear_rows()
    for check in parsed_report_output['DP Neighbor Auth EIGRP']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

3.3.2 Require OSPF Authentication if Protocol is Used 
    """
    table.clear_rows()
    for check in parsed_report_output['DP Neighbor Auth OSPF']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

3.3.3 Require RIPv2 Authentication if Protocol is Used
    """
    table.clear_rows()
    for check in parsed_report_output['DP Neighbor Auth RIP']:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant'], configuration_tab_replace(check['Current Configuration'])])
    report_body += f"""
{table}

3.3.4 Require BGP Authentication if Protocol is Used
    """
    table.clear_rows()
    table.add_row([parsed_report_output['DP Neighbor Auth BGP']['CIS Check'], parsed_report_output['DP Neighbor Auth BGP']['Level'], 
                   parsed_report_output['DP Neighbor Auth BGP']['Compliant'], 
                   configuration_tab_replace(parsed_report_output['DP Neighbor Auth BGP']['Current Configuration'])])
    report_body += f"""
{table}

============================================================================================================================================
    """
    
    print(report_summary)
    print(report_body)