import pandas as pd
import pprint
import re
import os

logfile = open(r"C:\Users\visha\Documents\vs code\LogPearsing\serverlogs.log")

pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"

ip_addrs_list = []
failed_list=[]
success_list=[]
for log in logfile:
    ip_add=re.search(pattern, log)
    ip_addrs_list.append(ip_add.group())
    list=log.split(" ")
    failed_list.append(str(list[-1]))
    success_list.append(str(list[-4]))

df=pd.DataFrame(coloums=['IP Address', "Success", "Failed"])
df['IP Address']= ip_addrs_list
df["Success"] = success_list
df["Failed"]= failed_list

pprint.pprint(df)