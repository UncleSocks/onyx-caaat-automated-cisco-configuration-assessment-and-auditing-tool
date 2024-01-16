from maskpass import askpass
from ssh_module import ssh_login
from version_check import ios_version_check
from audit_modules.caaat15 import run_cis_cisco_ios_15_assessment
from logo import logo


if __name__ == "__main__":

    print(logo())

    ip_address = input("Target: ")
    username = input("Username: ")
    password = askpass("Password: ")
    enable_password = askpass("Enable: ")

    try:
        print(f"\nConnecting to target Cisco router {ip_address} via SSH...")
        connection = ssh_login(ip_address, username, password, enable_password)
    except:
        print("Error 0001 - Unable to login to the target router, check IP address and login credentials.")
        print("Exiting the Onyx: CAAAT...")
        exit()

    print("Identifying Ciso IOS version...")
    ios_version = ios_version_check(connection)

    if ios_version == 15:
        print("Ciso IOS version: 15")
        print("Running CIS Ciso IOS 15 Benchmark assessment...\n")
        run_cis_cisco_ios_15_assessment(connection)
    
    elif ios_version == 17:
        print("Running CIS Ciso IOS 17 Benchmark assessment...")
    
    else:
        print("Error 0002 - Unable to identify Cisco IOS version.")

    print("Closing SSH connection...")
    connection.disconnect