import csv
import os
import json
import jbxapi
import tldextract
import datetime
from pathlib import Path
domainlist = []
from dotenv import load_dotenv

whitelist = ["google.com","bing.com","microsoft.com","sendgrid.net","adobe.com","google.co.uk","sharepoint.com","rs6.net","mimecast.com","canva.com","targetx.com","canon-europe.com","ipfs.io","outlook.com"]

##Grab API Key######
load_dotenv("jsb.env")
key = os.getenv("API_KEY")
joe = jbxapi.JoeSandbox(apikey=key)

##BUILD CSV FILE#####
IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "joesandboxiocs+" + stamp + ".csv"
fopen = Path(filename)

if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)

##Query user
query = input("what is the string to search in JSB? ")
hashlist = []
y = joe.analysis_search(query)#query to search

#print(json.dumps(y, sort_keys=True, indent=4, separators=(',', ':'))) use this for analyzing output

##Grab URLs
for z in y:
    if z['detection'] == "malicious" or z['detection'] == "suspicious":
        domain = tldextract.extract(z["filename"])
        if domain.suffix != "":
            domainTLD= domain.domain + "." + domain.suffix #Block at highest level where possible
            if domainTLD not in domainlist and domainTLD not in whitelist:
                domainlist.append(domainTLD)

##Grab SHA256
for z in y:
    if (z['detection'] == "malicious" or z['detection'] == "suspicious") and z['sha256'] != "":
        hashlist.append(z['sha256'])    

##Write To File
with open(filename, 'a',newline='') as file:
    writer = csv.writer(file)
    for i in domainlist:#DomainName
        writer.writerow(["DomainName",i,"","Block","","IOC","IOC","","","","","FALSE"])#Create MDE BlockList
    for i in hashlist: 
        writer.writerow(["FileSha256",i,"","Block","","IOC","IOC","","","","","FALSE"])
        print("https://www.virustotal.com/gui/file/"+i)#verify hash result 
        
print(domainlist) #print URL list

