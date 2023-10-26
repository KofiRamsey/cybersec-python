import subprocess, platform

os_name = platform.system()
if os_name == "Windows":
    list_networks_command = 'netsh wlan show networks'
    output = subprocess.check_output(list_networks_command, shell=True, text=True)

    print(output)
elif os_name == "Linux":
    list_networks_command = "nmcli device wifi list"
    output = subprocess.check_output(list_networks_command, shell=True, text=True)

    print(output)
else:
    print("Unsupported OS")
