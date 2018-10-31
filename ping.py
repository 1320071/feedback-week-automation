import os
import subprocess
import sys
import nmap
import cPickle as pickle
import nmapParse

# rpcclient credentials
username = "test"
password = "test123"

# returns whether host responds to ping or not
def ping(host):
    os.system("ping -c 1 " + host + " > " + host + ".txt")
    pingFile = open(host + ".txt", 'r')
    os.system("rm " + host + ".txt")
    for num, line in enumerate(pingFile):
        if num == 1:
            if 'Unreachable' in line:
                print 'Unreachable'
                return False
            else:
                print 'Reachable'
                return True

# Runs an nmap scan on the host and parses using nmapParse.py
def scan(host):
    print "Scanning " + host
    scanner = nmap.PortScanner()
    scanner.scan(host, arguments="-sV -O --script vuln")
	return scanner[host]

# Uses rpcclient to enumerate for dom users
# Writes list of users to host/users.txt
# Runs rpcQueryUser for each user found
def rpcEnumDomUsers(host):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c enumdomusers > " + host + "/users.txt")
    userFile = open(host + "/users.txt")
    users = []
    for line in userFile:
        users.append(line[6:-14])
    os.system("mkdir " + host + "/users")
    for user in users:
        rpcQueryUser(host, user)
    return usersn  

# Uses rpcclient to enumerate info about individual users
# Writes the info to host/users/user.txt
def rpcQueryUser(host, user):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c \'queryuser \"" + user + "\"\' > " + host + "/users/\'" + user + ".txt\'")

# Uses rpcclient to enumerate for all group types
# Writes the groups to host/groups.txt
def rpcEnumGroups(host):
    commands = ['enumdomgroups', '\'enumalsgroups builtin\'', '\'enumalsgroups domain\'']
    for i in commands:
        os.system("rpcclient " + host + " -U " + username + "%" + password + " -c " + i + " >> " + host + "/groups.txt")

# Sorts user txt files into folders of their respective groups
def getUserGroupNames(host):
    occupiedGroups = []
    userGroupId = {}
    usersDir = os.listdir(host + "/users")
    groups = open(host + "/groups.txt", 'r')

    # Populates userGroupId dict with the users and their group ids
    for user in usersDir:
        tempUserFile = open(host + "/users/" + user)
        for i, line in enumerate(tempUserFile):
            if i == 0:
                # Slice name from line 0
                nm = line[15:-1]
            if i == 18:
                # Slice group id from line 18
                gid = line[12:-1]
        userGroupId[nm] = gid
    
    # Creates a directory to sort the users into
    os.system("mkdir " + host + "/sortedUsers")

    # For each group
    for group in groups:
        # Make a folder of that groups name
        os.system("mkdir " + host + "/sortedUsers/\'" + group[7:-14] + "\'")
        # For each user
        for user in userGroupId:
            # Check if user is in the current group
            if userGroupId[user] == group[-7:-2]:
                # If so, move their .txt file into that group folder
                os.system("mv " + host + "/users/\'" + user + ".txt\' " + host + "/sortedUsers/\'" + group[7:-14] + "\'/")
                # Add group to the list of occupied groups
                if group[7:-14] not in occupiedGroups:
                    occupiedGroups.append(group[7:-14])
    
    # For all occupied groups
    for group in occupiedGroups:
        # Move the groups folder to host/users
        os.system("mv " + host + "/sortedUsers/\'" + group + "\'" + " " + host + "/users")
    # Remove unoccupied folders
    os.system("rm -r " + host + "/sortedUsers")

if __name__ == "__main__":
    hosts = sys.argv[1:]
    for host in hosts:
        if ping(host):
			# init html out
            os.system("mkdir " + host)

            nmapOutput = scan(host)

            rpcEnumDomUsers(host)
            rpcEnumGroups(host)
            getUserGroupNames(host)
