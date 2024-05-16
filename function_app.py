import datetime
import logging
import azure.functions as func
import json, gc, os, requests, threading, csv
from azure.storage.blob import BlobServiceClient
from io import StringIO

app = func.FunctionApp()

# region Global variables
ak= os.environ.get("ACCESS_KEY")
secret = os.environ.get("SECRET")
region = "api4"
connection_string = os.environ.get("CONNECTION_STRING")
container_name = "compliance-standard-reports"
container_name1 = "assets-by-comp-and-enviroment"
container_name2 = 'historial-compliance-standard-reports'

# region API requests
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
    response=json.loads(response.content)
    
    # Token of Prisma Cloud session
    return response['token']

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

def compliance_porture(compliance_id,account_group):

    url="https://{}.prismacloud.io/v2/compliance/posture/{}".format(region,compliance_id)

    payload={"timeType":"to_now","timeUnit":"epoch",'account.group':account_group}
    headers={
        "Accept": "application/json; charset=UTF-8",
        "x-redlock-auth": token()
    }

    response=requests.request("GET",url,headers=headers,params=payload)                                                                                  
    response=json.loads(response.content)
    return response['requirementSummaries']

def assets_explorer(account_group,compliance_name,requirement_name,section_id):

    url = "https://{}.prismacloud.io/v2/resource/scan_info".format(region)

    payload={
        "account.group": account_group,
        "timeType":"to_now",
        "timeUnit":"epoch",
        "policy.complianceStandard":compliance_name,
        "policy.complianceRequirement":requirement_name,
        "policy.complianceSection": section_id
        #"limit": 50
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

def policy_severity(policy_id):

    url="https://{}.prismacloud.io/policy/{}".format(region,policy_id)

    headers={
        'Accept': 'application/json; charset=UTF-8',
        'x-redlock-auth': token()
    }

    response=requests.request('GET',url,headers=headers)
    response=json.loads(response.content)

    #string
    return response['severity']

# region Handler functions
def send_dicts_to_blob_storage(data, blob_service_client, container_name, blob_name):

    desired_order = ['Cloud','Compliance Standard','Section ID','Section Description','Requirement','Resource','Account ID','Account Name','Enviroment','Severity','Passed']
    reordered_list = []
    for item in data:
        reordered_dict = {key: item[key] for key in desired_order if key in item}
        reordered_list.append(reordered_dict)
    data=reordered_list

    csv_string = StringIO()
    writer = csv.writer(csv_string)
    writer.writerow(data[0].keys())  # Write header row
    for item in data:
        writer.writerow(list(item.values()))

    #Upload the CSV data to the blob
    try:
        blob_client = blob_service_client.get_blob_client(container_name, blob_name)
        blob_client.upload_blob(csv_string.getvalue(), content_type="text/csv", overwrite=True)
        print(f"Data successfully uploaded to blob '{blob_name}' in container '{container_name}'.")
        logging.info(f"Data successfully uploaded to blob '{blob_name}' in container '{container_name}'.")
    except Exception as e:
        print(f"Error uploading data: {e}")
        logging.info(f"Error uploading data: {e}")

# def row_creation():

def row_maker(main_data,asset,compliance_name,cloud,ambiente,section,requirement_name):

    # severity_guide=['','informational','low','medium','high','critical']
    # severities=asset['scannedPolicies']
    if asset == {}:

        asset={
            'name':'Resource not readable outside Prisma Cloud',
            'accountId':'Unknow_More info in Prisma Cloud',
            'accountName':'Unknow_More info in Prisma Cloud'
        }

        passed='Unknow'

        if section['associatedPolicyIds']!=[]:

            severity=policy_severity(section['associatedPolicyIds'][0])

        else:

            severity='Not assigned policy'
            
    else:
        severity=asset['scannedPolicies'][0]['severity']
        passed=asset['scannedPolicies'][0]['passed']

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

    del row

    gc.collect()

def row_creation(main_data,cloud,compliance_name,section,requirement_name,ambiente,passed):

    if section['associatedPolicyIds']!=[]:
        severity=policy_severity(section['associatedPolicyIds'][0])
    else:
        severity='No policies associated to this control'
    row={
        'Cloud':cloud,
        'Compliance Standard': compliance_name,
        'Section ID': section['sectionId'],
        'Section Description': section['description'],
        'Requirement': requirement_name,
        'Resource': "Please visit https://app4.prismacloud.io for more information about the name of this resource",
        'Account ID': "Please visit https://app4.prismacloud.io for more information about the name of this resource",
        'Account Name': "Please visit https://app4.prismacloud.io for more information about the name of this resource",
        'Enviroment': ambiente,
        'Severity': severity,
        'Passed': passed
    }
    main_data.append(row.copy())

    del row

def data_maker(main_data,account_group,compliance_name,requirement_name,section,cloud,ambiente,compliancePosture):

    allAssests=assets_explorer(account_group,compliance_name,requirement_name,section['sectionId'])
    if allAssests != [] and allAssests != {}:
        for asset in allAssests:
            
            # row_maker(main_data,asset,compliance_name,cloud,ambiente,section,requirement_name)
            t=threading.Thread(target=row_maker, args=[main_data,asset,compliance_name,cloud,ambiente,section,requirement_name])
            t.start()
        
        try:
            t.join()
            logging.info('Data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
            print('Data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
            
        except:
            logging.info('Error adding {} of {}'.format(section['sectionId'],compliance_name))
            print('Error adding {} of {}'.format(section['sectionId'],compliance_name))
    else:
        try:
            for req in compliancePosture:
                if req['name']==requirement_name:
                    for x in req['sectionSummaries']:
                        if x['id']==section['id']:
                            try:
                                for _ in range(int(x['failedResources'])):
                                    # row_creation(main_data,cloud,compliance_name,section,requirement_name,ambiente,"FALSE")
                                    t2=threading.Thread(target=row_creation, args=[main_data,cloud,compliance_name,section,requirement_name,ambiente,"FALSE"])
                                    t2.start()
                                t2.join()
                                logging.info('Failed data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                                print('Failed data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                            except:
                                logging.info('No failed resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                                print('No failed resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))

                            try:
                                for _ in range(int(x['passedResources'])):
                                    # row_creation(main_data,cloud,compliance_name,section,requirement_name,ambiente,"TRUE")
                                    t=threading.Thread(target=row_creation, args=[main_data,cloud,compliance_name,section,requirement_name,ambiente,"TRUE"])
                                    t.start()
                                t.join()
                                logging.info('Passed data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                                print('Passed data created for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                            except:
                                logging.info('No passed resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
                                print('No passed resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
        except:
            logging.info('No resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))
            print('No resources found for {} {} {}'.format(section['sectionId'],section['description'],compliance_name))

# region Handlers
def comp_report(compliance,accountGroup,ambiente,cloud,turbo=False):

    dataMain=[]
    
    allCompliances=all_compliance_standards()

    compliance_id=""

    for x in allCompliances:
        
        if compliance == x['name']:

            compliance_id=x['id']
            break

    else:

        print('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))
        logging.info('{} compliance standard was not found in Prisma Cloud\nSkipping this compliance standard...'.format(compliance))

    #[{"description":"Ensure that...","id":"","name":"iam","requirementId":"1",...},...]
    allRequirements=all_compliance_requirements(compliance_id)

    #[{"id":"String","name":"Storgae","sectionSummaries":[{"failedResources":int,"passedResources":int,"totalResources":int,"id":"String":"name":"2.2.1"}]},...]
    compliancePosture=compliance_porture(compliance_id,accountGroup)
    print(compliancePosture)

    for requirement in allRequirements:

        requirement_id=requirement['id']
        requirement_name=requirement['name']
        allSections=all_sections_of_a_compliance_requirement(requirement_id)

        for section in allSections:
            if turbo == False:
                data_maker(dataMain,accountGroup,compliance,requirement_name,section,cloud,ambiente,compliancePosture)
            elif turbo == True:  
                t=threading.Thread(target=data_maker, args=[dataMain,accountGroup,compliance,requirement_name,section,cloud,ambiente,compliancePosture])  
                t.start()
        
        if turbo == True:
            t.join()

    blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    nowvalue = datetime.datetime.now()
    dt_string = nowvalue.strftime("%Y-%m-%d")

    send_dicts_to_blob_storage(dataMain,blob_service_client,container_name1,'currentanalysis-'+cloud+ambiente+'.csv')
    send_dicts_to_blob_storage(dataMain,blob_service_client,container_name2,'analysis-'+cloud+ambiente+dt_string+".csv")

    logging.info('Blob created successfully!')

    del dataMain

def merge_csv_from_blob(cloud,ambiente):

    blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    # Download CSV data as strings
    try:
        name='currentanalysis-'+cloud+ambiente[0]+'.csv'
        blob_client = blob_service_client.get_blob_client(container=container_name1, blob=name)
        data1 = blob_client.download_blob(max_concurrency=1, encoding='UTF-8')
        print(data1)
        data1 = data1.readall()
    except:
        print('currentanalysis-'+cloud+ambiente[0]+'.csv was not found')
        logging.info('currentanalysis-'+cloud+ambiente[0]+'.csv was not found')
        data1 = ''

    try:
        name='currentanalysis-'+cloud+ambiente[1]+'.csv'
        blob_client = blob_service_client.get_blob_client(container=container_name1, blob=name)
        data2 = blob_client.download_blob(max_concurrency=1, encoding='UTF-8')
        print(data2)
        data2 = data2.readall() 
    except:
        print('currentanalysis-'+cloud+ambiente[1]+'.csv was not found')
        logging.info('currentanalysis-'+cloud+ambiente[1]+'.csv was not found')
        data2 = ''

    try:
        name='currentanalysis-'+cloud+ambiente[2]+'.csv'
        blob_client = blob_service_client.get_blob_client(container=container_name1, blob=name)
        data3 = blob_client.download_blob(max_concurrency=1, encoding='UTF-8')
        print(data3)
        data3 = data3.readall()
    except:
        print('currentanalysis-'+cloud+ambiente[2]+'.csv was not found')
        logging.info('currentanalysis-'+cloud+ambiente[2]+'.csv was not found')
        data3 = ''

    # Combine data, ensuring newlines between files
    merged_data = data1+data2+data3

    # Get output container client
    blob_client = blob_service_client.get_blob_client(container=container_name,blob='currentanalysis-'+cloud+'.csv')

    # Upload merged data to output file
    blob_client.upload_blob(merged_data,content_type='text/csv',overwrite=True)

    print(f"Merged CSV files into: {'currentanalysis-'+cloud+'.csv'}")
    logging.info(f"Merged CSV files into: {'currentanalysis-'+cloud+'.csv'}")

# region Azure Functions
@app.schedule(schedule="0 0 10,22 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def azure_report_pdn(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura Azure PDN V 1.0','Azure PDN Account Group','Produccion','azure',True)

@app.schedule(schedule="0 20 10,22 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def azure_report_lab(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura Azure LAB V 1.0','Azure LAB Account Group','Laboratorio','azure')

@app.schedule(schedule="0 40 10,22 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def azure_report_dll(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura Azure DLLO V 1.0','Azure DLLO Account Group','Desarrollo','azure')

@app.schedule(schedule="0 00 11,23 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def aws_report_pdn(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura AWS PDN V 1.0','AWS PDN Account Group','Produccion','aws')

@app.schedule(schedule="0 20 11,23 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def aws_report_lab(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura AWS LAB V 1.0','AWS LAB Account Group','Laboratorio','aws')

@app.schedule(schedule="0 40 11,23 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def aws_report_dll(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura AWS DLLO V 1.0','AWS DLLO Account Group','Desarrollo','aws')

@app.schedule(schedule="0 0 12,0 * * *", arg_name="mytimer", run_on_startup=True,
              use_monitor=False) 
def oci_report_pdn(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura OCI PDN V 1.0','OCI PDN Account Group','Produccion','oci')

@app.schedule(schedule="0 20 12,0 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def oci_report_lab(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura OCI LAB V 1.0','OCI LAB Account Group','Laboratorio','oci')

@app.schedule(schedule="0 40 12,0 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def oci_report_dll(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    comp_report('Estandar Sura OCI DLLO V 1.0','OCI DLLO Account Group','Desarrollo','oci')

@app.schedule(schedule="0 0 13,1 * * *", arg_name="mytimer", run_on_startup=False,
              use_monitor=False) 
def merger(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.UTC).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')
    
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    ambientes=['Produccion','Desarrollo','Laboratorio']
    clouds=['aws','oci','azure']
    for cloud in clouds:
        merge_csv_from_blob(cloud,ambientes)

# region Debugging
def general_debugging():
    comp_report('Estandar Sura OCI PDN V 1.0','OCI PDN Account Group','Produccion','oci')
    comp_report('Estandar Sura OCI LAB V 1.0','OCI LAB Account Group','Laboratorio','oci')
    comp_report('Estandar Sura OCI DLLO V 1.0','OCI DLLO Account Group','Desarrollo','oci')
    comp_report('Estandar Sura Azure PDN V 1.0','Azure PDN Account Group','Produccion','azure',True)
    comp_report('Estandar Sura Azure LAB V 1.0','Azure LAB Account Group','Laboratorio','azure')
    comp_report('Estandar Sura Azure DLLO V 1.0','Azure DLLO Account Group','Desarrollo','azure')
    comp_report('Estandar Sura AWS PDN V 1.0','AWS PDN Account Group','Produccion','aws')
    comp_report('Estandar Sura AWS LAB V 1.0','AWS LAB Account Group','Laboratorio','aws')
    comp_report('Estandar Sura AWS DLLO V 1.0','AWS DLLO Account Group','Desarrollo','aws')
    ambientes=['Produccion','Desarrollo','Laboratorio']
    clouds=['aws','oci','azure']
    for cloud in clouds:
        merge_csv_from_blob(cloud,ambientes)

# print(all_compliance_requirements('c9efa28a-56b3-4166-bf95-8adfb4fb2306'))
# print(compliance_porture('c9efa28a-56b3-4166-bf95-8adfb4fb2306'))
# general_debugging()
