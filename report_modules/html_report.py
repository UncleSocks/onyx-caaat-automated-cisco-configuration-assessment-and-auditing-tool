from datetime import datetime

def report_html_output_ios15(parsed_report_output, compliance_score_dict, html_filename, target_ip_address, ios_version):

    html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width", initial-scale="1.0">
            <title>ONYX: Cisco Another Automated Assessment Tool Report</title>
            <link rel="icon" href="./assets/icon.png" type="image/x-icon">
            <link rel="stylesheet" href="html_report_styles.css">
            <script src="html_report_script.js"></script>
        </head>
        <body>
            <div class="header">
                <div class="logo"></div>
                <div class="title">
                    <p>CIS Cisco IOS Benchmark Assessment Report</p>
                </div>
                <div class="bar"></div>
            </div>
            <div class="summary-container">
                <div class="summary-title">
                    <div class="summary-font">
                        Report Summary
                    </div>
                    <div class="date">
                        <p>Report Generated: {datetime.now()}</p>
                    </div>
                </div>
                <div class="summary-body">
                    <div class="target">
                        <p id="target-font">Target Details</p>
                        <p>Target: {target_ip_address}
                        <p>IOS Version: {ios_version}
                    </div>
                    <div class="passed">
                        <p id="score-font">Passed Checks</p>
                        <div class="summary-bar"></div>
                        <p><span id="score-value">{compliance_score_dict['Total Passed Checks']}</span> out of {compliance_score_dict['Total Checks']} total assessment checks</p>
                    </div>
                    <div class="failed">
                        <p id="score-font">Failed Checks</p>
                        <div class="summary-bar"></div>
                        <p><span id="score-value">{compliance_score_dict['Total Failed Checks']}</span> out of {compliance_score_dict['Total Checks']} total assessment checks</p>
                    </div>
                    <div class="na">
                        <p id="score-font">Not Applicable</p>
                        <div class="summary-bar"></div>
                        <p><span id="score-value">{compliance_score_dict['Total NA Checks']}</span> checks were not applicable</p>
                    </div>
                </div>
            <div class="plane">
                <div class="management">
                    <p id="plane-font">Management Plane</p>
                    <p><span id="plane-value-passed">{compliance_score_dict['Passed Management Plane Checks']}</span> checks passed; <span id="plane-value-failed">{compliance_score_dict['Failed Management Plane Checks']}</span> checks failed; <span id="plane-value-na">{compliance_score_dict['NA Management Plane Checks']}</span> not applicable checks</p>
                </div>
                <div class="control">
                    <p id="plane-font">Control Plane</p>
                    <p><span id="plane-value-passed">{compliance_score_dict['Passed Control Plane Checks']}</span> checks passed; <span id="plane-value-failed">{compliance_score_dict['Failed Control Plane Checks']}</span> checks failed; <span id="plane-value-na">{compliance_score_dict['NA Control Plane Checks']}</span> not applicable checks</p>
                </div>
                <div class="data">
                    <p id="plane-font">Data Plane</p>
                    <p><span id="plane-value-passed">{compliance_score_dict['Passed Data Plane Checks']}</span> checks passed; <span id="plane-value-failed">{compliance_score_dict['Failed Data Plane Checks']}</span> checks failed; <span id="plane-value-na">{compliance_score_dict['NA Data Plane Checks']}</span> not applicable checks</p>
                </div>
            </div>
            </div>
            <div class="table-container">
                <div class="table-header">
                    <p class="table-header-font">Assessment Breakdown</p>
                    <div class="table-bar"></div>
                </div>
                <div class="table-section">
                    <p id="section-font">Management Plane</p>
                </div>
                <table class="expandable-table">
                    <thead class="table-top-font">
                        <th>CIS CHECK</th>
                        <th>LEVEL</th>
                        <th>COMPLIANT</th>
                    </thead>
                    <thead class="table-subsection">
                        <th colspan="3">1.1 Local Authentication, Authorization and Accounting (AAA) Rules</th>
                    </thead>
        """
    for check in parsed_report_output['MP Local AAA Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">1.2 Access Rules</th>
                    </thead>
    """
    for check in parsed_report_output['MP Access Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">1.3 Banner Rules</th>
                    </thead>
    """
    for check in parsed_report_output['MP Banner Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">1.4 Password Rules</th>
                    </thead>
    """
    for check in parsed_report_output['MP Password Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">1.5 SNMP Rules</th>
                    </thead>
    """
    for check in parsed_report_output['MP SNMP Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
            </table>
                <div class="table-section">
                    <p id="section-font">Control Plane</p>
                </div>
                <table class="expandable-table">
                    <thead class="table-top-font">
                        <th>CIS CHECK</th>
                        <th>LEVEL</th>
                        <th>COMPLIANT</th>
                    </thead>
                    <thead class="table-subsection">
                        <th colspan="3">2.1 Global Services Rules</th>
                    </thead>
                    <thead class="table-subsection">
                        <th colspan="3">2.1.1 Setup SSH</th>
                    </thead>
    """
    for check in parsed_report_output['CP Global Services SSH Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    for check in parsed_report_output['CP Global Services Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">2.2 Logging Rules</th>
                    </thead>
    """
    for check in parsed_report_output['CP Logging Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">2.3 NTP Rules</th>
                    </thead>
    """
    for check in parsed_report_output['CP NTP Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">2.4 Loopback Rules</th>
                    </thead>
    """
    for check in parsed_report_output['CP Loopback Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
            </table>
                <div class="table-section">
                    <p id="section-font">Data Plane</p>
                </div>
                <table class="expandable-table">
                    <thead class="table-top-font">
                        <th>CIS CHECK</th>
                        <th>LEVEL</th>
                        <th>COMPLIANT</th>
                    </thead>
                    <thead class="table-subsection">
                        <th colspan="3">3.1 Routing Rules</th>
                    </thead>
    """
    for check in parsed_report_output['DP Routing Rules']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">3.3 Neighbor Authentication</th>
                    </thead>
                    <thead class="table-subsection">
                        <th colspan="3">3.3.1 Require EIGRP Authentication if Protocol is Used</th>
                    </thead>
    """
    for check in parsed_report_output['DP Neighbor Auth EIGRP']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">3.3.2 Require OSPF Authentication if Protocol is Used</th>
                    </thead>
    """
    for check in parsed_report_output['DP Neighbor Auth OSPF']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">3.3.3 Require RIPv2 Authentication if Protocol is Used</th>
                    </thead>
    """
    for check in parsed_report_output['DP Neighbor Auth RIP']:
        html_report += f"""
                    <tr class="expandable-row">
                        <td class="toggle-btn">{check['CIS Check']}</td>
                        <td class="toggle-btn">{check['Level']}</td>
                        <td class="toggle-btn">{check['Compliant']}</td>
                    </tr>
                    <tr class="expanded-content">
                        <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                            <p>{check['Current Configuration']}
                        </td>
                    </tr>
                """
    html_report += """
                    <thead class="table-subsection">
                        <th colspan="3">3.3.4 Require BGP Authentication if Protocol is Used</th>
                    </thead>
    """
    html_report += f"""
                <tr class="expandable-row">
                    <td class="toggle-btn">{parsed_report_output['DP Neighbor Auth BGP']['CIS Check']}</td>
                    <td class="toggle-btn">{parsed_report_output['DP Neighbor Auth BGP']['Level']}</td>
                    <td class="toggle-btn">{parsed_report_output['DP Neighbor Auth BGP']['Compliant']}</td>
                </tr>
                <tr class="expanded-content">
                    <td colspan="3"><span id="current-config-font">CURRENT CONFIGURATION</span>
                        <p>{parsed_report_output['DP Neighbor Auth BGP']['Current Configuration']}
                    </td>
                </tr>
            """
    html_report += """
                </table>
            </div>
        </body>
        </html>
    """
    with open(f'./report_modules/{html_filename}', 'w') as file:
        file.write(html_report)