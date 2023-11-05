## Joe Sandbox to MDE BlockList ###

Create a search term to grab IOCs from JSB e.g. "phish" or "malicious" or "malware" or even a TLD like "xyz"  

Results can then be uploaded to tenant Allow Block List. 

Proof of concept, creates a CSV in the same directory as script that can be uploaded to MDE:  

![image](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/assets/55988027/db91bef8-7537-4aa8-afe2-e28eb6163717)

![image](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/assets/55988027/42c01dc6-d536-4db0-9675-b8259ff116f2)

![image](https://github.com/jkerai1/JoeSandBoxToMDEBlockList/assets/55988027/e120669a-07ce-4b6a-b7f2-2fa36a9711b0)

File naming convention is joesandboxiocs+{thedate}.csv  

API key goes into the env file  

Whitelist is available 

Modify tldextract to extract at different levels I have gone for IOC at highest level which may not make sense  

No duplication checks between runs :) however MDE natively handles duplicates  

Do not blindly upload, validate results before uploading   

TABL does not support punycode (xn--)
