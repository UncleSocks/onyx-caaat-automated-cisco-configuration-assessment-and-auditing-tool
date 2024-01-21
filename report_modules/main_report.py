from prettytable import PrettyTable


def generate_report(cis_check, level, compliant, current_configuration):
    current_check = {'CIS Check':cis_check, 'Level':level, 'Compliant':compliant, 'Current Configuration':current_configuration}
    return current_check
    

def report_cli_output(report_output, compliance_score):
    
    total_passed_compliance_score = compliance_score['Passed Management Plane Checks'] + compliance_score['Passed Control Plane Checks'] + compliance_score['Passed Data Plane Checks']
    total_failed_compliance_score = compliance_score['Failed Management Plane Checks'] + compliance_score['Failed Control Plane Checks'] + compliance_score['Failed Data Plane Checks']
    total_na_compliance_score = compliance_score['NA Management Plane Checks'] + compliance_score['NA Control Plane Checks'] + compliance_score['NA Data Plane Checks']

    mp_local_aaa_rules = report_output[0:11]
    mp_access_rules = report_output[11:15]
    mp_banner_rules = report_output[15:18]
    mp_password_rules = report_output[18:21]
    mp_snmp_rules = report_output[21:31]

    cp_global_service_rules_ssh = report_output[31:44]
    cp_logging_rules = report_output[44:51]
    cp_ntp_rules = report_output[51:56]
    cp_loopback_rules = report_output[56:60]

    dp_routing_rules = report_output[60:64]
    dp_neighbor_auth_eigrp = report_output[64:73]
    dp_neighbor_auth_ospf = report_output[73:75]
    dp_neighbor_auth_rip = report_output[75:80]
    dp_neighbor_auth_bgp = report_output[80]

    report_summary = f"""

==================================================================================================================    
                                                                                                                
                                    -- CIS CISCO IOS BENCHMARK ASSESSMENT REPORT -- 
------------------------------------------------------------------------------------------------------------------

                                                    REPORT SUMMARY
                                    ------------------------------------------------

+ Passed Compliance Checks: {total_passed_compliance_score}
+ Failed Compliance Checks: {total_failed_compliance_score}
+ Unchecked Compliance Checks: {total_na_compliance_score}

Compliance Score Breakdown

+ Management Plane: {compliance_score['Passed Management Plane Checks']} Passed; {compliance_score['Failed Management Plane Checks']} Failed; {compliance_score['NA Management Plane Checks']} Unchecked
+ Control Plane: {compliance_score['Passed Control Plane Checks']} Passed; {compliance_score['Failed Control Plane Checks']} Failed; {compliance_score['NA Control Plane Checks']} Unchecked
+ Data Plane: {compliance_score['Passed Data Plane Checks']} Passed; {compliance_score['Failed Data Plane Checks']} Failed; {compliance_score['NA Data Plane Checks']} Unchecked


    """
    table = PrettyTable()
    table.field_names = ['CIS Check', 'Level', 'Compliant']
    table.align['CIS Check'] = 'l'
    table.align['Level'] = 'c'
    table.align['Compliant'] = 'c'
    table._min_width = {'CIS Check':90}

    for check in report_output[0:31]:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])
    
    report_summary += f"""
                                                    MANAGEMENT PLANE
{table}
    """
    table.clear_rows()
    for check in report_output[31:60]:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])    
    report_summary += f"""
                                                     CONTROL PLANE
{table}
    """
    table.clear_rows()
    for check in report_output[60:80]:
        table.add_row([check['CIS Check'], check['Level'], check['Compliant']])    
    report_summary += f"""
                                                       DATA PLANE
{table}
    """
    
    report_body = f"""
                                                  ASSESSMENT BREAKDOWN
                                     ------------------------------------------------

==================================================================================================================

1. MANAGEMENT PLANE


1.1 Local Authentication, Authorization and Accounting (AAA) Rules
------------------------------------------------------------------------------------------------------------------

"""
    for check in mp_local_aaa_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
1.2 Access Rules
------------------------------------------------------------------------------------------------------------------    
"""
    for check in mp_access_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
1.3 Banner Rules
------------------------------------------------------------------------------------------------------------------    
    """
    for check in mp_banner_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
1.4 Password Rules
------------------------------------------------------------------------------------------------------------------    
    """
    for check in mp_password_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
1.5 SNMP Rules
------------------------------------------------------------------------------------------------------------------    
    """
    for check in mp_snmp_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
    
------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------



2. Control Plane

2.1 Global Service Rules
------------------------------------------------------------------------------------------------------------------
2.1.1 Setup SSH
2.1.1.1 Configure Prerequisites for the SSH Service   
------------------------------------------------------------------------------------------------------------------ 
"""
    for check in cp_global_service_rules_ssh:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
2.2 Logging Rules    
------------------------------------------------------------------------------------------------------------------
    """
    for check in cp_logging_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
2.3 NTP Rules
------------------------------------------------------------------------------------------------------------------

2.3.1 Require Enryption Keys for NTP    
    """
    for check in cp_ntp_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """

2.4 Loopback Rules 
------------------------------------------------------------------------------------------------------------------
    """
    for check in cp_loopback_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------


3. Data Plane

3.1 Routing Rules
------------------------------------------------------------------------------------------------------------------
    """
    for check in dp_routing_rules:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
3.3 Neighbor Authentication
------------------------------------------------------------------------------------------------------------------

3.3.1 Require EIGRP Authentication if Protocol is Used
    """
    for check in dp_neighbor_auth_eigrp:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
3.3.2 Require OSPF Authentication if Protocol is Used 
    """
    for check in dp_neighbor_auth_ospf:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += """
3.3.3 Require RIPv2 Authentication if Protocol is Used
    """
    for check in dp_neighbor_auth_rip:
        report_body += f"""
CIS Check: {check['CIS Check']}
Level: {check['Level']}
Compliant: {check['Compliant']}
Current Configuration: {check['Current Configuration']}
        """
    report_body += f"""
3.3.4 Require BGP Authentication if Protocol is Used

CIS Check: {dp_neighbor_auth_bgp['CIS Check']}
Level: {dp_neighbor_auth_bgp['Level']}
Compliant: {dp_neighbor_auth_bgp['Compliant']}
Current Configuration: {dp_neighbor_auth_bgp['Current Configuration']}

==================================================================================================================
    """
    
    print(report_summary)
    print(report_body)