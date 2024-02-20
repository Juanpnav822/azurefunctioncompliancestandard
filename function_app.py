import logging
import azure.functions as func

app = func.FunctionApp()

@app.schedule(schedule="0 * * * * *", arg_name="myTimer", run_on_startup=True,
              use_monitor=False) 
def timer_trigger(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function executed.')

import json, requests, csv, os
from datetime import datetime
from azure.storage.blob import BlobServiceClient

# These are my global variables
ak= os.environ.get("ACCESS_KEY")
secret = os.environ.get("SECRET")
region = os.getenv("REGION")
connection_string = os.environ.get("CONNECTION_STRING")
container_name = "compliance-standard-reports"

def token():
    
    url="https://{}.prismacloud.io/login".format(region)

    payload={
        "username":ak,
        "password":secret
    }
    payload=json.dumps(payload)
    
    headers={
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    }

    response=requests.request("POST",url,headers=headers,data=payload)
    if response.status_code == 200:
        response=json.loads(response.content)
        # Token of Prisma Cloud session
        return response['token']
    
    else:
        print("Wrong credentials")

def all_compliance_standards():

    url="https://{}.prismacloud.io/compliance".format(region)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)
    
    #[{"cloudType":[],"id":"","name":"",...},...]
    return response

def all_compliance_requirements(compliance_id):

    url="https://{}.prismacloud.io/compliance/{}/requirement".format(region,compliance_id)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)

    #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
    return response

def all_sections_of_a_compliance_requirement(requirement_id):

    url="https://{}.prismacloud.io/compliance/{}/section".format(region,requirement_id)

    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers)
    response=json.loads(response.content)

    #[{"description":"","id":"","sectionId":""},...]
    return response

def assets_inventory(account_group,compliance_name,requirement_name,section_id):

    url = "https://{}.prismacloud.io/v2/resource/scan_info".format(region)

    payload={
        "account.group": account_group,
        "timeType":"to_now",
        "timeUnit":"epoch",
        "policy.complianceStandard":compliance_name,
        "policy.complianceRequirement":requirement_name,
        "policy.complianceSection": section_id
    }

    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token()
    }

    response=requests.request("GET",url,headers=headers,params=payload)
    response=json.loads(response.content)
    response=response['resources']

    #[{accountId:"",accountName:"",...},...]
    return response

def write_csv(data,filename):
    with open("{}.csv".format(filename), "w", newline="") as csvfile:
        fieldnames = data[0].keys()  # Extract keys from the first dictionary
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def report_maker(cloud_analysis,cloud):

    allComplianceStandards=all_compliance_standards()

    main_data=[]

    for compliance_name,account_group,ambiente in cloud_analysis:

        compliance_id=""

        for x in allComplianceStandards:
               
            if compliance_name == x['name']:

                compliance_id=x['id']
                break

        else:

            print('{} compliance standard was not found in Prisma Cloud for this analysis\nExiting this script...'.format(compliance_name))
            exit()
        
        #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
        allRequirements=all_compliance_requirements(compliance_id)

        for requirement in allRequirements:

            requirement_id=requirement['id']
            requirement_name=requirement['name']

            allSections=all_sections_of_a_compliance_requirement(requirement_id)

            for section in allSections:

                try:

                    allAssests=assets_inventory(account_group,compliance_name,requirement_name,section['sectionId'])

                    for asset in allAssests:
                        
                        severity_guide=['','informational','low','medium','high','critical']
                        severities=asset['scannedPolicies']
                        severity=asset['scannedPolicies'][0]['severity']
                        passed=asset['scannedPolicies'][0]['passed']

                        if len(severities) > 1:
                            
                            index=0

                            for x in severities:
                                for y in severity_guide:
                                    if x['severity']==y:
                                        if severity_guide.index(y) > index:
                                            severity=x['severity']
                                            index=severity_guide.index(y)

                            for x in severities:
                                if x['passed']==False:
                                    passed=False
                                    break

                        row={}
                        row={
                            'Cloud':cloud,
                            'Compliance Standard':compliance_name,
                            'Section ID': section['sectionId'],
                            'Section Description': section['description'],
                            'Requirement': requirement_name,
                            'Resource': asset['name'],
                            'Account ID': asset['accountId'],
                            'Account Name': asset['accountName'],
                            'Enviroment': ambiente,
                            'Severity': severity,
                            'Passed': passed
                        }

                        main_data.append(row.copy())
                
                except:

                    print('THERE IT WAS AN ERROR TRYING TO GET ASSETS INFO FOR SECTION ONE SECTION')
                
                print('Assets for "{} {} {} {} {}" was added to the report'.format(account_group,compliance_name,requirement_name,section['sectionId'],section['description']))

    nowvalue = datetime.now()
    dt_string = nowvalue.strftime("%Y-%m-%d_%H_%M_%S")

    write_csv(main_data,cloud+" Analysis "+dt_string)
    write_csv(main_data,"currentanalysis-"+cloud)

    blob_name="currentanalysis-"+cloud
    blob_name2=cloud+" Analysis "+dt_string

    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    blob_client = blob_service_client.get_blob_client(container_name, blob_name)
    blob_client2 = blob_service_client.get_blob_client("historial-compliance-standard-reports",blob_name2)

    try:
        with open(blob_name+".csv", "rb") as data:
            blob_client.upload_blob(data, overwrite=True)
            print(f"Blob uploaded successfully: {blob_name}")

        with open(blob_name2+".csv", "rb") as data:
            blob_client2.upload_blob(data, overwrite=True)
            print(f"Blob uploaded successfully: {blob_name2}")

    except Exception as e:
        print(f"Error uploading blob: {e}")

def handler():

    azure_analysis=[['Estandar Sura Azure PDN V 0.6','Azure PDN Account Group','Produccion'],
                    ['Estandar Sura Azure DLLO V 0.6','Azure DLLO Account Group','Desarrollo'],
                    ['Estandar Sura Azure LAB V 0.6','Azure LAB Account Group','Laboratorio']]
    aws_analysis=[['Estandar Sura AWS PDN V 0.6','AWS PDN Account Group','Produccion'],
                    ['Estandar Sura AWS DLLO V 0.6','AWS DLLO Account Group','Desarrollo'],
                    ['Estandar Sura AWS LAB V 0.6','AWS LAB Account Group','Laboratorio']]
    # oci_analysis=[['',''],['',''],['','']]

    report_maker(azure_analysis,'azure')
    report_maker(aws_analysis,'aws')
    #report_maker(oci_analysis,'oci')

handler()