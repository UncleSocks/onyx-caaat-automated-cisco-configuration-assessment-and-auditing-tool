

def report_html_output_ios15(report_output):
    
    
    
    html_report = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ONYX: Cisco Another Automated Assessment Tool Report</title>
        </head>
        <body>
            <h1>CIS Report</h1>
            <table border="1">
                <tr>
                    <th>CIS Check</th>
                    <th>Level</th>
                    <th>Compliant</th>
                    <th>Current Configuration</th>
                </tr>
    """
    html_report += """
                <tr>
                    <th colspan="4">1. Management Plane</th>
                </tr>
                <tr>
                    <td colspan="4">1.1 Local Authentication, Authorization and Accounting (AAA) Rule</td>
                </tr>
    """
    for output in report_output[0:11]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """
    html_report += """
                <tr>
                    <td colspan="4">1.2 Access Rule</td>
                </tr>            
    """
    for output in report_output[11:15]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """
        
    html_report += """
                <tr>
                    <td colspan="4">1.3 Banner Rules</td>
                </tr>            
    """

    for output in report_output[15:18]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">1.4 Password Rules</td>
                </tr>            
    """

    for output in report_output[18:21]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">1.5 SNMP Rules</td>
                </tr>            
    """

    for output in report_output[21:31]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """
        
    html_report += """
                <tr>
                    <th colspan="4">2. Control Plane</th>
                </tr>
                <tr>
                    <td colspan="4">2.1 Global Service Rules</td>
                </tr>
                <tr>
                    <td colspan="4">2.1.1 Setup SSH</td>
                </tr>
                <tr>
                    <td colspan="4">2.1.1.1 Configure Prerequisites for the SSH Service</td>
                </tr>
    """

    for output in report_output[31:44]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">2.2 Logging Rules</td>
                </tr>            
    """

    for output in report_output[44:51]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">2.3 NTP Rules</td>
                </tr>
                <tr>
                    <td colspan="4">2.3.1 Require Enryption Keys for NTP</td>
                </tr>
    """

    for output in report_output[51:56]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">2.4 Loopback Rules</td>
                </tr>            
    """

    for output in report_output[56:60]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <th colspan="4">3. Data Plane</th>
                </tr>
                <tr>
                    <td colspan="4">3.1 Routing Rules</td>
                </tr>
    """

    for output in report_output[60:64]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">3.3 Neighbor Authentication</td>
                </tr>
                <tr>
                    <td colspan="4">3.3.1 Require EIGRP Authentication if Protocol is Used</td>
                </tr>
    """

    for output in report_output[64:73]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">3.3.2 Require OSPF Authentication if Protocol is Used</td>
                </tr>
    """

    for output in report_output[73:75]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += """
                <tr>
                    <td colspan="4">3.3.3 Require RIPv2 Authentication if Protocol is Used</td>
                </tr>
    """

    for output in report_output[75:80]:
        html_report += f"""
                <tr>
                    <td>{output['CIS Check']}</td>
                    <td>{output['Level']}</td>
                    <td>{output['Compliant']}</td>
                    <td>{output['Current Configuration']}</td>
                </tr>
    """

    html_report += f"""
                <tr>
                    <td colspan="4">3.3.4 Require BGP Authentication if Protocol is Used</td>
                </tr>
                <tr>
                    <td>{report_output[80]['CIS Check']}</td>
                    <td>{report_output[80]['Level']}</td>
                    <td>{report_output[80]['Compliant']}</td>
                    <td>{report_output[80]['Current Configuration']}</td>
                </tr>
    """

    html_report += """
            </table>
        </body>
        </html>
    """
    with open('cis_checks_report.html', 'w') as f:
        f.write(html_report)