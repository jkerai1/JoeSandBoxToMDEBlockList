import csv
import os
import json
import jbxapi #pip install required lib
import tldextract
import datetime
from pathlib import Path
from dotenv import load_dotenv

domainlist = []
hashlist = []
whitelist = ["google.com","bing.com","microsoft.com","sendgrid.net","adobe.com","google.co.uk","sharepoint.com","rs6.net","mimecast.com","canva.com","targetx.com","canon-europe.com","ipfs.io","scc.com","outlook.com"]

load_dotenv("jsb.env") #Grab API Key from env
key = os.getenv("API_KEY")
joe = jbxapi.JoeSandbox(apikey=key,accept_tac=True)

#Build CSV File with column schema if file doesn't exist with timestamp, remove timestamp if not req'd for use case
IOC_Columns = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"]
stamp = datetime.datetime.now().strftime("%x").replace("/","-")
filename = "joesandboxiocs+" + stamp + ".csv"

if os.path.exists(filename)== False:
    with open(filename, 'a+',newline='') as file:
        writer = csv.writer(file)
        writer.writerow(IOC_Columns)
        
print("Tool Written by Jkerai1 https://github.com/jkerai1\n")
query = input("what is the string to search in JSB? ") #User Input could be removed and terms could be hardcoded
if query == "":
    query = "phish" #Fallback
    
y = joe.analysis_search(query) #print(json.dumps(y, sort_keys=True, indent=4, separators=(',', ':'))) #use this for analyzing output

#Grab IOCS, first URLs then SHA256
for z in y:
    if z['detection'] == "malicious" or z['detection'] == "suspicious":
        domain = tldextract.extract(z["filename"])
        if domain.suffix != "":
            domainAndTLD= domain.domain + "." + domain.suffix #Block at highest level where possible,modify as required.
            if domainAndTLD not in domainlist and domainAndTLD not in whitelist:
                domainlist.append(domainAndTLD)
for z in y:
    if (z['detection'] == "malicious" or z['detection'] == "suspicious") and z['sha256'] != "":
        hashlist.append(z['sha256'])   

with open(filename, 'a',newline='') as file:
    writer = csv.writer(file) #Write To File
    for i in domainlist:
        writer.writerow(["DomainName",i,"","Block","","JSB IOC","JSB IOC","","","","","FALSE"]) #Fields are generic but could be customized with information from the API Request e.g analysis ID or external reference like VT
    for i in hashlist: 
        writer.writerow(["FileSha256",i,"","Block","","JSB IOC","JSB IOC","","","","","FALSE"])
        print("https://www.virustotal.com/gui/file/"+i) #verify hash result with external source
