

def report_html_output_ios15(report_output):
    
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
    with open('./report_modules/cis_checks_report.html', 'w') as f:
        f.write(html_report)



report_output = [{'CIS Check': "1.1.1 Enable 'aaa new-model'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'no aaa new-model'}, 
                 {'CIS Check': "1.1.2 Enable 'aaa authentication login'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.1.3 Enable 'aaa authentication enable default'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.1.4 Set 'authentication login' for 'line con'", 'Level': 1, 'Compliant': True, 'Current Configuration': ' exec-timeout 0 0\n privilege level 15\n logging synchronous\n stopbits 1'}, {'CIS Check': "1.1.5 Set 'authentication login' for 'line tty'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.1.6 Set 'authentication login' for 'line vty'", 'Level': 1, 'Compliant': True, 'Current Configuration': ' login local\n transport input ssh'}, {'CIS Check': "1.1.7 Set 'aaa accounting' to log all privileged use commands using commands 15", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.1.8 Set 'aaa accounting connection'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.1.9 Set 'aaa accounting exec'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.1.10 Set 'aaa accounting network'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.1.11 Set 'aaa accounting system'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.2.1 Set 'privilege 1' for local users", 'Level': 1, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "1.2.2 Set 'transport input ssh' for 'line vty' connections", 'Level': 1, 'Compliant': True, 'Current Configuration': [{'Start': '0', 'End': '4', 'Transport Input': 'ssh'}]}, {'CIS Check': "1.2.4 Create 'access-list' for use with 'line vty'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.2.5 Set 'access-class' for 'line vty'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.3.1 Set the 'banner-text' for 'banner exec'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.3.2 Set the 'banner-text' for 'banner login'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.3.3 Set the 'banner-text' for 'banner motd'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.4.1 Set 'password' for 'enable secret'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, 
                 {'CIS Check': "1.4.2 Enable 'service password-encryption'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'no service password-encryption'}, 
                 {'CIS Check': "1.4.3 Set 'username secret' for all local users", 'Level': 1, 'Compliant': False, 'Current Configuration': [{'Username': 'admin', 'Secret': False, 'Config': 'password 0 password'}]}, 
                 {'CIS Check': "1.5.1 Set 'no snmp-server' to disable SNMP when unused", 'Level': 1, 'Compliant': False, 'Current Configuration': 'snmp agent enabled'}, 
                 {'CIS Check': "1.5.2 Unset private for 'snmp-server community'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'Community name: private\nCommunity SecurityName: private'}, 
                 {'CIS Check': "1.5.3 Unset public for 'snmp-server community'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'Community name: public\nCommunity SecurityName: public'}, 
                 {'CIS Check': "1.5.4 Do not set 'RW' for any 'snmp-server community'", 'Level': 1, 'Compliant': True, 'Current Configuration': [{'String': 'public', 'Access': 'RO'}, {'String': 'private', 'Access': 'RO'}, {'String': 'mouse', 'Access': 'RO'}]}, {'CIS Check': "1.5.5 Set the ACL for each 'snmp-server community'", 'Level': 1, 'Compliant': False, 'Current Configuration': [{'String': 'public', 'ACL': '2'}, {'String': 'private', 'ACL': None}, {'String': 'mouse', 'ACL': '5'}]}, {'CIS Check': "1.5.6 Create an 'access-list' for use with SNMP", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "1.5.7 Set 'snmp-server host' when using SNMP", 'Level': 1, 'Compliant': True, 'Current Configuration': 'snmp-server host 192.168.157.200 public  tty bgp config'}, {'CIS Check': "1.5.8 Set 'snmp-server enable traps snmp'", 'Level': 1, 'Compliant': True, 'Current Configuration': 'snmp-server enable traps snmp authentication linkdown linkup coldstart'}, {'CIS Check': "1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Groupname': 'ILMI', 'Security Models': ['v1', 'v2c']}, {'Groupname': 'mouse', 'Security Models': ['v1', 'v2c']}, {'Groupname': 'public', 'Security Models': ['v1', 'v2c']}, {'Groupname': 'private', 'Security Models': ['v1', 'v2c', 'v3 priv']}]}, {'CIS Check': "1.5.10 Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", 'Level': 2, 'Compliant': False, 'Current Configuration': [{'Username': 'mama', 'Authentication Protocol': 'SHA', 'Privacy Protocol': 'AES128', 'Groupname': 'private'}, {'Username': 'papa', 'Authentication Protocol': 'SHA', 'Privacy Protocol': 'AES128', 'Groupname': 'private'}, {'Username': 'brother', 'Authentication Protocol': 'None', 'Privacy Protocol': 'None', 'Groupname': 'public'}]}, {'CIS Check': "2.1.1.1.1 Set the 'hostname'", 'Level': 1, 'Compliant': True, 'Current Configuration': 'hostname R1'}, {'CIS Check': "2.1.1.1.2 Set the 'ip domain-name'", 'Level': 1, 'Compliant': True, 'Current Configuration': 'ip domain name dlsu.local'}, {'CIS Check': "2.1.1.1.3 Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'", 'Level': 1, 'Compliant': True, 'Current Configuration': '% Key pair was generated at: 17:07:16 UTC Dec 25 2023\nKey name: R1.dlsu.local\nKey type: RSA KEYS\n Storage Device: private-config\n Usage: General Purpose Key\n Key is not exportable.\n Key Data:\n  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 \n  00B76EF7 0A1F0862 A6F7BA11 D60EC5E3 1B303B9C D07DF8BD 31D4259A 152C6C2C \n  448D52FA C52FBCC2 5F549F99 2817D5F6 0FE4CE90 1B1A5F05 F834335D 258AEC94 \n  3D79EE73 A6CC3122 A712A84E E0A98239 B8C5AFEE 8C0A1466 6EF35BA0 32E3EC12 \n  C9AB49CD EEDBA058 7B863291 FE0610D2 363EE7CA 833FB6B0 A7AC00F4 73F54D8C \n  A037470F 39A50C2F 061A514C 120538AC 0A82AD0C D98EB8DA 1263F60B 3FC1B7B7 \n  8043AAB7 36C2FF6C A0444ABF E0B50E23 78660D19 54FA4DE4 AA03FBC9 5225B266 \n  3C74FEDF B303B010 4497A197 B5A9E1C4 9226982E 79F8419A 62F5B2C0 CD243DC5 \n  BE9C7124 6563C7D4 22E32AE2 5DA3B90D 348401DD 5952423A A19B8AB9 5884058B \n  31020301 0001\n% Key pair was generated at: 06:41:54 UTC Jan 18 2024\nKey name: R1.dlsu.local.server\nKey type: RSA KEYS\nTemporary key\n Usage: Encryption Key\n Key is not exportable.\n Key Data:\n  307C300D 06092A86 4886F70D 01010105 00036B00 30680261 00BB57AB 84CF66C2 \n  C01E7E81 8F262494 CB78B3F9 21931CBD F0CD1F21 5E138EAB 77311C8F CD172353 \n  1AF905AE 166A9261 9766B295 4678EA43 BD70DE43 D9521987 01D46E50 AE082B75 \n  48646F03 9CCD92C3 F8E69863 27B2128A 7E406E91 499B42B2 BF020301 0001'}, {'CIS Check': "2.1.1.1.4 Set 'seconds' for 'ip ssh timeout'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'Authentication Timeout - 120'}, {'CIS Check': "2.1.1.1.5 Set maximum value for 'ip ssh authentication-retries'", 'Level': 1, 'Compliant': True, 'Current Configuration': 'Authentication Retries - 3'}, {'CIS Check': "2.1.1.2 Set version 2 for 'ip ssh version'", 'Level': 1, 'Compliant': False, 'Current Configuration': {'Status': 'Enabled', 'Version': '1.99', 'Authentication Timeout': 120, 'Authentication Retries': 3}}, {'CIS Check': "2.1.2 Set 'no cdp run'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'Global CDP information:\n\tSending CDP packets every 60 seconds\n\tSending a holdtime value of 180 seconds\n\tSending CDPv2 advertisements is  enabled'}, {'CIS Check': "2.1.3 Set 'no ip bootp server'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.1.4 Set 'no service dhcp'", 'Level': 1, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "2.1.5 Set 'no ip identd'", 'Level': 1, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "2.1.6 Set 'service tcp-keepalives-in'", 'Level': 1, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "2.1.7 Set 'service tcp-keepalives-out'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.1.8 Set 'no service pad'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.2.1 Set 'logging on'", 'Level': 1, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "2.2.2 Set 'buffer size' for 'logging buffered'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.2.3 Set 'logging console critical'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.2.4 Set IP address for 'logging host'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.2.5 Set 'logging trap informational'", 'Level': 1, 'Compliant': False, 'Current Configuration': 'Trap logging: level informational, 13 message lines logged'}, {'CIS Check': "2.2.6 Set 'service timestamps debug datetime'", 'Level': 1, 'Compliant': True, 'Current Configuration': 'service timestamps debug datetime msec'}, {'CIS Check': "2.2.7 Set 'logging source interface", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.3.1.1 Set 'ntp authenticate'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.3.1.2 Set 'ntp authentication-key'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.3.1.3 Set the 'ntp trusted key'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.3.1.4 Set 'key' for each 'ntp server'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.3.2 Set 'ip address' for 'ntp server'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.4.1 Create a single 'interface loopback'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.4.2 Set AAA 'source-interface'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.4.3 Set 'ntp source' to Loopback Interface", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "2.4.4 Set 'ip tftp source-interface' to the Loopback Interface", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "3.1.1 Set 'no ip source-route'", 'Level': 1, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "3.1.2 Set 'no ip proxy-arp'", 'Level': 2, 'Compliant': False, 'Current Configuration': [{'Interface': 'FastEthernet0/0', 'Proxy ARP': 'enabled'}]}, {'CIS Check': "3.1.3 Set 'no interface tunnel;", 'Level': 2, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "3.1.4 Set 'ip verify unicast source reachable-via'", 'Level': 2, 'Compliant': True, 'Current Configuration': None}, {'CIS Check': "3.3.1.1 Set 'key chain'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.1.2 Set 'key'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.1.3 Set 'key-string'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.1.4 Set 'address-family ipv4 autonomous-system", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'VRF': 'DLSU', 'Autonomous System': '100'}]}, {'CIS Check': "3.3.1.5 Set 'af-interface default'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'VRF': 'DLSU', 'AF Interface': ['default']}]}, {'CIS Check': "3.3.1.6 Set 'authentication key-chain", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'VRF': 'DLSU', 'Auth Key Chain': ['MYCHAIN']}]}, {'CIS Check': "3.3.1.7 Set 'authentication mode md5'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'VRF': 'DLSU', 'Auth Mode': ['md5']}]}, {'CIS Check': "3.3.1.8 Set 'ip authentication key-chain eigrp", 'Level': 2, 'Compliant': True, 'Current Configuration': ' ip rip authentication key-chain MYCHAIN\n   authentication key-chain MYCHAIN'}, {'CIS Check': "3.3.1.9 Set 'ip authentication mode eigrp'", 'Level': 2, 'Compliant': True, 'Current Configuration': ' ip rip authentication mode md5\n   authentication mode md5'}, {'CIS Check': "3.3.2.1 Set 'authentication message-digest' for OSPF area", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Process ID': '10', 'Area Number': '100', 'Authentication': 'message-digest'}]}, {'CIS Check': "3.3.2.2 Set 'ip ospf message-digest-key md5'", 'Level': 2, 'Compliant': False, 'Current Configuration': None}, {'CIS Check': "3.3.3.1 Set 'key chain'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.3.2 Set 'key'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.3.3 Set 'key-string", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Key Chain': 'MYCHAIN', 'Key': '10', 'Key String': 'secureroute'}]}, {'CIS Check': "3.3.3.4 Set 'ip rip authentication key-chain", 'Level': 2, 'Compliant': True, 'Current Configuration': ' ip rip authentication key-chain MYCHAIN'}, {'CIS Check': "3.3.3.5 Set 'rip ip authentication mode'", 'Level': 2, 'Compliant': True, 'Current Configuration': ' ip rip authentication mode md5'}, {'CIS Check': "3.3.4.1 Set 'neighbor password'", 'Level': 2, 'Compliant': True, 'Current Configuration': [{'Autonomous System': '10', 'Neighbor': [{'Neighbor': '1.1.2.2', 'Peer-Group': 'DLSU', 'Password': None}, {'Neighbor': '1.1.3.3', 'Peer-Group': None, 'Password': 'test'}, {'Neighbor': '1.1.4.4', 'Peer-Group': 'UPC', 'Password': None}], 'Peer-Group': [{'Peer': 'DLSU', 'Password': 'test'}, {'Peer': 'UPC', 'Password': 'TEST'}]}]}]


#report_html_output_ios15(report_output)