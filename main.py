from maskpass import askpass
from ssh_module import ssh_login
from audit_modules.caaat15 import run_cis_cisco_ios_15_assessment


if __name__ == "__main__":
    ip_address = input("Target: ")
    username = input("Username: ")
    password = askpass("Password: ")
    enable_password = askpass("Enable: ")

    try:
        connection = ssh_login(ip_address, username, password, enable_password)
    except:
        print("Error 0001 - Unable to login to the target router, check IP address and login credentials.")
        print("Exiting the Onyx: CAAAT...")
        exit()

    run_cis_cisco_ios_15_assessment(connection)

    print("Closing connection")
    connection.disconnect