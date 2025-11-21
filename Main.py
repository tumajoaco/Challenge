#######Global Variables#############
PROJECT_FOLDER=""
CONFIG_FOLDER=""
ALERT_FOLDER=""
INCIDENT_FOLDER=""
SUMMARY_FOLDER=""
LOG_FOLDER=""
CONNECTORS_FILENAME=""
ALLOWLIST_FILENAME=""
MITRE_FILENAME=""
MARKDOWN_TEMPLATE_FILENAME=""
###################################

####Importing libraries######

try:
  import sys
  import json
  import yaml
  import os
  from jinja2 import Template
  from datetime import datetime
  print("Starting Main.py script")
except ImportError:
  print("Error loading modules, please verify that all required modules are installed")
  exit()
####################################################

#################################################
# Comments: This function check folder structure 

def Func_PreparingLogs():
  try:
    logsFile  = open(os.path.join(PROJECT_FOLDER,LOG_FOLDER,"logs.txt"),'a')
    logsIsolation = open(os.path.join(PROJECT_FOLDER,LOG_FOLDER,"isolation.txt"),'a')
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Starting Main.py script.\n")
  except:
    print("There was an error preparing the logs file, please review that the out folder exists.")

  return logsFile, logsIsolation
##################################################

########FUNC READ CONFIG CONNECTORS FILE########
# Comments: This function read files in config folder 

def Func_ReadConfigFiles():
  global PROJECT_FOLDER
  global CONFIG_FOLDER
  global ALERT_FOLDER
  global INCIDENT_FOLDER
  global SUMMARY_FOLDER
  global LOG_FOLDER
  global MOCK_FOLDER
  global CONNECTORS_FILENAME
  global ALLOWLIST_FILENAME
  global MITRE_FILENAME
  global MARKDOWN_TEMPLATE_FILENAME

  script_dir = os.path.dirname(os.path.abspath(__file__))
  try:

    with open(os.path.join(script_dir,"MainConfig.yaml"), 'r') as file:
      ConfigData = yaml.safe_load(file)
      PROJECT_FOLDER = script_dir
      CONFIG_FOLDER = ConfigData['FoldersPath']['ConfigFolderPath']
      ALERT_FOLDER = ConfigData['FoldersPath']['AlertsFolderPath']
      INCIDENT_FOLDER = ConfigData['FoldersPath']['IncidentFolderPath']
      SUMMARY_FOLDER = ConfigData['FoldersPath']['SummaryFolderPath']
      LOG_FOLDER = ConfigData['FoldersPath']['LogFolderPath']
      MOCK_FOLDER = ConfigData['FoldersPath']['MockDataFolderPath']
      CONNECTORS_FILENAME = ConfigData['FilesName']['ConnectorsFileName']
      ALLOWLIST_FILENAME = ConfigData['FilesName']['AllowlistFileName']
      MITRE_FILENAME = ConfigData['FilesName']['MitreMapFileName']
      MARKDOWN_TEMPLATE_FILENAME = ConfigData['FilesName']['MarkdownTemplateFileName']

    logsFile  = open(os.path.join(PROJECT_FOLDER,LOG_FOLDER,"logs.txt"),'a')
    logsIsolation = open(os.path.join(PROJECT_FOLDER,LOG_FOLDER,"isolation.txt"),'a')
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Starting Main.py script.\n")
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Reading Config Files.\n")

    with open(os.path.join(PROJECT_FOLDER,CONFIG_FOLDER,CONNECTORS_FILENAME), 'r') as file:
      connectorsData = yaml.safe_load(file)
    with open(os.path.join(PROJECT_FOLDER,CONFIG_FOLDER,ALLOWLIST_FILENAME), 'r') as file:
      allowListData = yaml.safe_load(file)
    with open(os.path.join(PROJECT_FOLDER,CONFIG_FOLDER,MITRE_FILENAME), 'r') as file:
      mitreMapData = yaml.safe_load(file)
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Config files have been loaded successfully.\n")

  except: 
    print(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Error during files configuration reading, please check the existance of the required files and folders.\n")
    print(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Error during files configuration reading, please check the existance of the required files and folders.\n")
    exit()

  return allowListData, connectorsData, mitreMapData, logsFile, logsIsolation
##############################################

########FUNC READ ALERT#########################
# Comments: This function read the alert that was inserted using arguments

def Func_ReadAlert(logsFile):
  if len(sys.argv) < 2:
    print("Please use the following convention to call the function python main.py alerts/sentinel.json")
    exit()

  try:
    with open( sys.argv[1], 'r') as file:
      alertData = json.load(file)  # Parses the JSON data into a Python dictionary/list
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: {sys.argv[1]} alert file read successfully.\n")

  except:
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} Error reading The file '{filePath}' please verify the presence and the format of it.\n")
    exit()
  return alertData

#####################

########FUNC ALERT NORMALIZATION########
# Comments: This function normalize the incident using the alert that was inserted using arguments

def Func_AlertNormalization(alertData, logsFile):

  #Calculate Incident number
  incidentId = 1
  while True:
    fileName=f"inc-{incidentId:003}.json"
    if os.path.exists(os.path.join(PROJECT_FOLDER,INCIDENT_FOLDER,fileName)):
      incidentId+=1
    else:
      break

  #IOC normalization
  indicators=[]
  for iocType, valueList in alertData['indicators'].items():
    for value in valueList:
       indicators.append( {"type":iocType, "value":value, "risk":{}, "allowlisted": False} )

  ####Converting URLS IOC into DOMAINS URLS#####

  #create INCIDENT json object

  incidentData = {
   "incident_id": f"inc-{incidentId:003}",
   "source_alert": alertData,
   "asset": alertData['asset'],
   "indicators": indicators,
   "triage": {
     "severity": 0,
     "bucket":"",
     "tags":[],
     "suppressed": False
   },
   "mitre": {
     "techniques":[]
   },
   "actions": [],
   "timeline": [
                {"stage":"ingest","ts":f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}","details":f"Alert {alertData['alert_id']} ingested."}
   ]   
  }

  logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Incident {incidentData['incident_id']} normalized successfully.\n")
  return incidentData

#####################

########VERIFY IOC#########
# Comments: this is an auxiliar function that receives the ioc and connectorsData list and check if the ioc is present TI provider

def Func_VerifyIoc(ioc, connectorsData, logsFile):
  logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Analyzing IOC {ioc['value']}.\n")
  foundIocs = []
  providers=connectorsData.get("providers")
  
  for providerName,filePath in providers.items():
    if filePath['base_url'].startswith("file"):
      ##MOCK FILE USAGE##
      folderPath = os.path.join(PROJECT_FOLDER,filePath['base_url'].replace("file://",""))
      for fileName in os.listdir(folderPath):
        if providerName in fileName and ioc['value'] in fileName and ioc['type'].replace("ipv4","ip").replace("ipv6","ip") in fileName :
           try:
             with open( os.path.join(PROJECT_FOLDER,folderPath,fileName), 'r') as FileIoc:
               iocData = json.load(FileIoc)
               iocData["provider"]=providerName
               foundIocs.append(iocData)
           except:
             logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Error reading the file {fileName}.\n")
             exit()
    else:
      ##NO MOCK FILES###
      logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Undesired conditions reading ti files.\n")
  
  if len(foundIocs):
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: For the IOC {ioc['value']}, {len(foundIocs)} matches have been found in the TI providers.\n")

  return foundIocs  

###########################

########ENRICH Incident########
# Comments: this function enriches the incident using the ioc lost from the TI provider defined in the connectorsData file

def Func_EnrichIncident(incidentData, connectorsData, logsFile):

  #Searching IOCS
  veredictPriority = ["malicious", "suspicious", "clean", "unknown"]
  indicatorsArray = []

  for index in range(len(incidentData['indicators'])):
    foundIocs = Func_VerifyIoc(incidentData['indicators'][index], connectorsData, logsFile)
    if foundIocs:
      ##Merging IOC
      veredicts=[]
      scores=[]
      providers=[]
      for ioc in foundIocs: 
        veredicts.append(ioc.get('risk') or ioc.get('reputation') or ioc.get('classification') or "unknown")
        scores.append(ioc.get('confidence') or ioc.get('score') or "0")
        providers.append(ioc['provider'])
      incidentData['indicators'][index]['risk']  = { 
        "veredict": next((p for p in veredictPriority if p in veredicts), None),
        "score": max(scores),
        "sources": providers
      } 
    else:
      incidentData['indicators'][index]['risk']  = { 
        "veredict": "Unknown",
        "score": 0,
        "sources": []     
      } 

    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: IOC {incidentData['indicators'][index]['value']}, Type: {incidentData['indicators'][index]['type']}, Veredict:{incidentData['indicators'][index]['risk']['veredict']}, Score:{incidentData['indicators'][index]['risk']['score']}, TI_Sources:{incidentData['indicators'][index]['risk']['sources']}.\n")

  logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Incident {incidentData['incident_id']} was enriched successfully.\n")
  incidentData['timeline'].append( {"stage":"enrich","ts":f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}","details":f"{len(incidentData['indicators'])} IOCs have been processed."})

  return incidentData

############################

########TRIAGE Incident########
# Comments: this function triage the incident using the enriched incident, allow list data and mitre information

def Func_TriageIncident(incidentData, allowListData, mitreMapData, logsFile):
  
  severityScore = 0

##AlertType
  match incidentData['source_alert']['type']:
    case 'Malware':
      severityScore+=70
    case 'Phishing':
      severityScore+=60
    case 'Beaconing':
      severityScore+=65
    case 'CredentialAccess':
      severityScore+=75
    case 'C2':
      severityScore+=80
    case _:
      severityScore+=40

##
  severityIoc=0
  malicious_quant=0
  malicious_allowListed_quant=0
  suspicious_quant=0
  suspicious_allowListed_quant=0
  iocQuantity=len(incidentData['indicators'])

  for index in range(iocQuantity):
    if(incidentData['indicators'][index]['value'] in allowListData['indicators'][incidentData['indicators'][index]['type']]):
      incidentData['indicators'][index]['allowlisted'] = True
      (incidentData['triage']['tags']).append(f"IOC {incidentData['indicators'][index]['value']} allowlisted=true") 
      if  (incidentData['indicators'][index]['risk']['veredict'] == 'malicious'): 
        malicious_allowListed_quant += 1
      else: ##suspicious
        suspicious_allowListed_quant += 1
      logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: IOC {incidentData['indicators'][index]['value']} allowlisted=true.\n")
    else:
    ##  incidentData['indicators'][index]['allowlisted']  = False
      if  (incidentData['indicators'][index]['risk']['veredict'] == 'malicious'): 
        malicious_quant += 1
      elif  (incidentData['indicators'][index]['risk']['veredict'] == 'suspicious'):
        suspicious_quant += 1
      else:
        None
  
  if ( (malicious_allowListed_quant+suspicious_allowListed_quant) == iocQuantity ):
    severityScore = 0
    incidentData['triage']['suppressed'] = True
    (incidentData['triage']['tags']).append('suppressed=true') 

  else:
    if(malicious_quant > 0):
      severityScore+=20
    elif(suspicious_quant > 0):
      severityScore+=10
    
    extra_flagged = (malicious_quant + suspicious_quant) - 1
    if extra_flagged > 0:
      severityScore += min(extra_flagged * 5, 20)
    
    if ((malicious_allowListed_quant+suspicious_allowListed_quant) > 0):
      severityScore -= 25

  #Clamp
  severityScore = max (0, min(severityScore,100))
  
  #Bucket
  if severityScore == 0:
    severity = "Suppressed"
  elif severityScore <= 39:
    severity = "Low"
  elif severityScore <= 69:
    severity = "Medium"
  elif severityScore <= 89:
    severity = "High"
  else:
    severity = "Critical"

  incidentData['triage']['severity'] = severityScore 
  incidentData['triage']['bucket'] = severity

  ##Mitre Tagging
  try:
    incidentData['mitre']['techniques'] = mitreMapData['types'][incidentData['source_alert']['type']]
  except:
    incidentData['mitre']['techniques'] =  mitreMapData['defaults']

  logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: IncidentId: {incidentData['incident_id']};\n     AlertType: {incidentData['source_alert']['type']};\n     IOCs: total->{iocQuantity}, malicious->{malicious_quant}, suspicious->{suspicious_quant}, allowedList->{malicious_allowListed_quant+suspicious_allowListed_quant};\n     Results: severity->{incidentData['triage']['severity']}, bucket->{incidentData['triage']['bucket']}.\n")

  logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Incident {incidentData['incident_id']} was triaged successfully.\n")
  incidentData['timeline'].append( {"stage":"triage","ts":f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}","details":f"severity:{incidentData['triage']['severity']}, bucket:{incidentData['triage']['bucket']}"})
  return incidentData

#################################  
########OUTPUT Incident########

def Func_OutputIncident(incidentData, allowListData, logsFile, logsIsolation):

  isolationOutput="Device was not isolated."
  if( incidentData['triage']['severity'] >= 70 ):
    try:
      if (incidentData['source_alert']['asset'].get('device_id') not in allowListData['assets']['device_ids']):
        logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Isolate device_id={incidentData['source_alert']['asset']['device_id']}  incident={incidentData['incident_id']} result=isolated.\n")
        logsIsolation.write(f"{datetime.now().isoformat(timespec='seconds')}: Isolate device_id = {incidentData['source_alert']['asset']['device_id']}  incident = {incidentData['incident_id']} result = isolated.\n")
        isolationOutput="Device was isolated."
        incidentData['actions'].append({"type":"isolate", "target":f"{incidentData['source_alert']['asset'].get('device_id') }", "result":"isolated", "ts":f"{datetime.now().isoformat(timespec='seconds')}"})
      else:
        (incidentData['triage']['tags']).append(f'{incidentData['source_alert']['asset'].get('device_id')} allowlisted=true') 
        isolationOutput="Device is in allowed list."

    except:
      None
      ##Device ID not present in alert

  incidentData['timeline'].append( {"stage":"respond","ts":f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}","details":f"{isolationOutput}"})
  

  ##SAVING INC IN JSON FORMAT
  try:
     incidentJsonString = json.dumps(incidentData, indent=4)
     IncJsonFile = open(os.path.join(PROJECT_FOLDER,INCIDENT_FOLDER,f'{incidentData['incident_id']}.json'), 'w')
     IncJsonFile.write(incidentJsonString )
     logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Incident {incidentData['incident_id']} output process was finished successfully. Incident information was stored in file {incidentData['incident_id']}.json at folder {INCIDENT_FOLDER}.\n")
  except:
     logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Error saving incident {incidentData['incident_id']} in file {incidentData['incident_id']}.json at folder {INCIDENT_FOLDER}.\n")

  ##SAVING INC IN MD FORMAT
  try:
    markdownTemplate = Template((open(os.path.join(PROJECT_FOLDER,SUMMARY_FOLDER,MARKDOWN_TEMPLATE_FILENAME), 'r')).read())
    incidentMarkdownOutput = markdownTemplate.render(incident=incidentData)
    IncMdFile = open(os.path.join(PROJECT_FOLDER,SUMMARY_FOLDER,f'{incidentData['incident_id']}.md'), 'w')
    IncMdFile.write(incidentMarkdownOutput)
    logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Incident {incidentData['incident_id']} output process was finished successfully. Incident information was stored in file {incidentData['incident_id']}.md at folder {SUMMARY_FOLDER}.\n\n\n\n")
  except:
     logsFile.write(f"{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}: Error saving incident {incidentData['incident_id']} in file {incidentData['incident_id']}.md at folder {SUMMARY_FOLDER}.\n\n\n\n") 
  return incidentData

#################################

def main():
  allowListData, connectorsData, mitreMapData, logsFile, logsIsolation = Func_ReadConfigFiles()
  alertData = Func_ReadAlert(logsFile)
  incidentData = Func_AlertNormalization(alertData, logsFile)
  incidentData = Func_EnrichIncident(incidentData, connectorsData, logsFile)
  incidentData = Func_TriageIncident(incidentData, allowListData, mitreMapData, logsFile)
  incidentData = Func_OutputIncident(incidentData, allowListData, logsFile, logsIsolation)
  print(f"Main.py script finished with no errors, incident {incidentData['incident_id']} created.")
  exit()

if __name__ == "__main__":
  main()