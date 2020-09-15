# this program parses a rule file and checks to see when an ip matches a rule
# increments a counter for when a rule is triggered and outputs it
# if it finds a matching IP, then increment
#
# Quincy Lam

import socket

rule_path = "RuleList.txt"
rules = {} # empty dictionary that will contain the key and value items to look for

# reads in the rules file and parses it
def readRules():
    f = open(rule_path, "r")
    for line in f:
        line_var = line.split() # splits each line
        rule_list = rules.get(line_var[0], {}) # get the specified item from the rules list and return an empty array if nothing is found
        
        if line_var[0] == "ip_src" or line_var[0] == "ip_dst":
            ip_string = socket.gethostbyname(line_var[1])
            rule_list[ip_string] = rule_list.get(ip_string, 0) # add target to the list
        else:
            rule_list[line_var[1]] = rule_list.get(line_var[1], 0) # add target to the list

        rules[line_var[0]] = rule_list # set new list back into rules
    print rules