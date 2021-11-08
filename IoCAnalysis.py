import os
import pandas as pd
from xml.etree import ElementTree as ET

# Get the data files
path = '../VMRay Dataset/'
file_list = os.listdir(path)
target_file = pd.read_csv('../family_name.csv')
print(file_list)

# Namespace definition
stix = '{http://stix.mitre.org/stix-1}'
stixCommon = '{http://stix.mitre.org/common-1}'
cybox = '{http://cybox.mitre.org/cybox-2}'
cyboxCommon = '{http://cybox.mitre.org/common-2}'
ProcessObj = '{http://cybox.mitre.org/objects#ProcessObject-2}'
AddressObj = '{http://cybox.mitre.org/objects#AddressObject-2}'
DNSRecordObj = '{http://cybox.mitre.org/objects#DNSRecordObject-2}'
URIObj = '{http://cybox.mitre.org/objects#URIObject-2}'
FileObj = '{http://cybox.mitre.org/objects#FileObject-2}'
indicator = '{http://stix.mitre.org/Indicator-2}'

# Result dataframe
result = pd.DataFrame()

# Extract artifacts values from all the 87 data files and make a .csv dataset file.
for file in file_list:
    # Extract XML elements
    tree = ET.parse(path + file)
    root = tree.getroot()
    stix_Observables = root.find(stix + 'Observables')
    stix_Indicators = root.find(stix + 'Indicators')
    cybox_Observable = stix_Observables.findall(cybox + 'Observable')
    cybox_Object = [element.find(cybox + 'Object') for element in cybox_Observable]
    cybox_Properties = [element.find(cybox + 'Properties') for element in cybox_Object]
    ProcessObj_Image_Info = [element.find(ProcessObj + 'Image_Info') for element in cybox_Properties]
    stix_Indicator = stix_Indicators.find(stix + 'Indicator')
    indicator_Related_Indicators = stix_Indicator.find(indicator + 'Related_Indicators')
    indicator_Related_Indicator = indicator_Related_Indicators.find(indicator + 'Related_Indicator')
    stixCommon_Indicator = indicator_Related_Indicator.find(stixCommon + 'Indicator')
    indicator_Observable = stixCommon_Indicator.find(indicator + 'Observable')
    indicator_cybox_Object = indicator_Observable.find(cybox + 'Object')
    indicator_cybox_Properties = indicator_cybox_Object.find(cybox + 'Properties')
    DNSRecordObj_Domain_Name = [element.find(DNSRecordObj + 'Domain_Name') for element in cybox_Properties]

    # Extract values
    xml_file_name = file.replace('.xml', '')
    address_list = [element.findtext(AddressObj + 'Address_Value') for element in cybox_Properties]
    dns_list = [element.findtext(URIObj + 'Value') if element is not None else None for element in DNSRecordObj_Domain_Name]
    pid_list = [element.findtext(ProcessObj + 'PID') for element in cybox_Properties]
    process_name_list = [element.findtext(ProcessObj + 'Name') for element in cybox_Properties]
    parent_pid_list = [element.findtext(ProcessObj + 'Parent_PID') for element in cybox_Properties]
    process_path_list = [element.findtext(ProcessObj + 'Path') if element is not None else None for element in ProcessObj_Image_Info]
    file_name_list = [element.findtext(FileObj + 'File_Name') for element in cybox_Properties]
    file_path_list = [element.findtext(FileObj + 'Full_Path') for element in cybox_Properties]
    indicator_name = indicator_cybox_Properties.findtext(FileObj + 'File_Name')

    print('Lengths:', len(address_list), len(pid_list), len(process_name_list), len(parent_pid_list),
          len(process_path_list), len(file_name_list), len(file_path_list), len(indicator_name))

    # Make a data with the extracted values
    df = pd.DataFrame({'xml_file_name': xml_file_name, 'Address': address_list, 'DNS': dns_list, 'PID': pid_list,
                       'Process_Name': process_name_list, 'Parent_PID': parent_pid_list, 'Process_Path': process_path_list,
                       'File_Name': file_name_list, 'File_Path': file_path_list, 'Indicator_File_Name': indicator_name})

    # Extract sum of values or representative value for each feature
    address = df['Address'].unique()
    if len(address) != 1:
        address = address[1]
    else:
        address = None
    dns = df['DNS'].unique()
    if len(dns) != 1:
        dns = dns[1]
    else:
        dns = None
    pid_num = df['PID'].notna().sum()
    process_name = df['Process_Name'].unique()[1]
    parent_pid_num = df['Parent_PID'].notna().sum()
    process_path = df['Process_Path'].unique()[1]
    file_num = df['File_Name'].notna().sum()
    file_path = ''
    for p in df['File_Path'].unique()[1:]:
        if p[:2] == 'c:':
            file_path = p
            break

    print('columns =', ['file_name', 'Address', 'DNS', 'PID', 'Process_Name', 'Parent_PID', 'Process_Path', 'File', 'File_Path', 'Indicator_File_Name'])
    print('values =', xml_file_name, address, dns, pid_num, process_name, parent_pid_num, process_path, file_num, file_path, indicator_name)

    # Add a organized record to a result dataset.
    result = result.append(pd.DataFrame({'file_name': [xml_file_name], 'Address': [address], 'DNS': [dns], 'PID': [pid_num], 'Process_Name': [process_name],
                                         'Parent_PID': [parent_pid_num], 'Process_Path': [process_path], 'File': [file_num], 'File_Path': [file_path], 'Indicator_File_Name': [indicator_name]}), ignore_index=True)

result = pd.merge(result, target_file)
result.to_csv('IoC_dataset.csv')
print(result)
