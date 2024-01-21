

def report_html_output_ios15(report_output, html_filename):
    
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
    
    html_report = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ONYX: Cisco Another Automated Assessment Tool Report</title>
            <link rel="stylesheet" href="html_report_styles.css">
        </head>
        <body>
            <table id="report">
                <caption>Cisco IOS 15 Benchmark Assessment Report</caption>
                <thead>
                    <tr>
                        <th>CIS Check</th>
                        <th>Level</th>
                        <th>Compliant</th>
                        <th>Current Configuration</th>
                    </tr>
                </thead>
                <tbody>
    """
    html_report += """
                    <tr>
                        <th colspan="4" id="section">1. Management Plane</th>
                    </tr>
                    <tr>
                        <td colspan="4" id="subsection">1.1 Local Authentication, Authorization and Accounting (AAA) Rule</td>
                    </tr>
    """
    for check in mp_local_aaa_rules:
        html_report += f"""
                    <tr>
                        <td>{check['CIS Check']}</td>
                        <td>{check['Level']}</td>
                        <td>{check['Compliant']}</td>
                        <td>{check['Current Configuration']}</td>
                    </tr>
        """
    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">1.2 Access Rule</td>
                    </tr>            
    """
    for check in mp_access_rules:
        html_report += f"""
                    <tr>
                        <td>{check['CIS Check']}</td>
                        <td>{check['Level']}</td>
                        <td>{check['Compliant']}</td>
                        <td>{check['Current Configuration']}</td>
                    </tr>
        """
        
    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">1.3 Banner Rules</td>
                    </tr>            
    """

    for check in mp_banner_rules:
        html_report += f"""
                    <tr>
                        <td>{check['CIS Check']}</td>
                        <td>{check['Level']}</td>
                        <td>{check['Compliant']}</td>
                        <td>{check['Current Configuration']}</td>
                    </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">1.4 Password Rules</td>
                    </tr>            
    """

    for check in mp_password_rules:
        html_report += f"""
                    <tr>
                        <td>{check['CIS Check']}</td>
                        <td>{check['Level']}</td>
                        <td>{check['Compliant']}</td>
                        <td>{check['Current Configuration']}</td>
                    </tr>
    """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">1.5 SNMP Rules</td>
                    </tr>            
    """

    for check in mp_snmp_rules:
        html_report += f"""
                    <tr>
                        <td>{check['CIS Check']}</td>
                        <td>{check['Level']}</td>
                        <td>{check['Compliant']}</td>
                        <td>{check['Current Configuration']}</td>
                    </tr>
        """
        
    html_report += """
                    <tr>
                        <th colspan="4" id="section">2. Control Plane</th>
                    </tr>
                    <tr>
                        <td colspan="4" id="subsection">2.1 Global Service Rules</td>
                    </tr>
                    <tr>
                        <td colspan="4">2.1.1 Setup SSH</td>
                    </tr>
                    <tr>
                        <td colspan="4">2.1.1.1 Configure Prerequisites for the SSH Service</td>
                    </tr>
    """

    for check in cp_global_service_rules_ssh:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">2.2 Logging Rules</td>
                    </tr>            
    """

    for check in cp_logging_rules:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">2.3 NTP Rules</td>
                    </tr>
                    <tr>
                        <td colspan="4">2.3.1 Require Enryption Keys for NTP</td>
                    </tr>
    """

    for check in cp_ntp_rules:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">2.4 Loopback Rules</td>
                    </tr>            
    """

    for check in cp_loopback_rules:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <th colspan="4" id="section">3. Data Plane</th>
                    </tr>
                    <tr>
                        <td colspan="4" id="subsection">3.1 Routing Rules</td>
                    </tr>
    """

    for check in dp_routing_rules:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4" id="subsection">3.3 Neighbor Authentication</td>
                    </tr>
                    <tr>
                        <td colspan="4">3.3.1 Require EIGRP Authentication if Protocol is Used</td>
                    </tr>
    """

    for check in dp_neighbor_auth_eigrp:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4">3.3.2 Require OSPF Authentication if Protocol is Used</td>
                    </tr>
    """

    for check in dp_neighbor_auth_ospf:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += """
                    <tr>
                        <td colspan="4">3.3.3 Require RIPv2 Authentication if Protocol is Used</td>
                    </tr>
    """

    for check in dp_neighbor_auth_rip:
        html_report += f"""
                        <tr>
                            <td>{check['CIS Check']}</td>
                            <td>{check['Level']}</td>
                            <td>{check['Compliant']}</td>
                            <td>{check['Current Configuration']}</td>
                        </tr>
        """

    html_report += f"""
                    <tr>
                        <td colspan="4">3.3.4 Require BGP Authentication if Protocol is Used</td>
                    </tr>
                    <tr>
                        <td>{dp_neighbor_auth_bgp['CIS Check']}</td>
                        <td>{dp_neighbor_auth_bgp['Level']}</td>
                        <td>{dp_neighbor_auth_bgp['Compliant']}</td>
                        <td>{dp_neighbor_auth_bgp['Current Configuration']}</td>
                    </tr>
    """

    html_report += """
                </tbody>
            </table>
        </body>
        </html>
    """
    with open(f'./report_modules/{html_filename}', 'w') as file:
        file.write(html_report)