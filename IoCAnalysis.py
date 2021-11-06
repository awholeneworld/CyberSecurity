import os
import pandas as pd
from xml.etree import ElementTree as ET

# Get the data files
path = 'C:/Users/samsung/Desktop/VMRay Dataset/'
file_list = os.listdir(path)
print(file_list)

# Namespace definition
stix = '{http://stix.mitre.org/stix-1}'
cybox = '{http://cybox.mitre.org/cybox-2}'
ProcessObj = '{http://cybox.mitre.org/objects#ProcessObject-2}'

# Extract artifacts values from all the 87 data files
# and make a .csv dataset file.
for file in file_list:
    tree = ET.parse(path + file)
    root = tree.getroot()
    stix_Observables = root.find(stix + 'Observables')
    cybox_Observable = stix_Observables.findall(cybox + 'Observable')
    cybox_Object = [element.find(cybox + 'Object') for element in cybox_Observable]
    cybox_Properties = [element.find(cybox + 'Properties') for element in cybox_Object]
    ProcessObj_Image_Info = [element.find(ProcessObj + 'Image_Info') for element in cybox_Properties if element is not None]

    # None이면 File이나 WinRegistryKey 정보인 것->추후 가져오는 코드 추가하기

    pid_list = [element.findtext(ProcessObj + 'PID') for element in cybox_Properties]
    name_list = [element.findtext(ProcessObj + 'Name') for element in cybox_Properties]
    parent_pid_list = [element.findtext(ProcessObj + 'Parent_PID') for element in cybox_Properties]
    path_list = [element.findtext(ProcessObj + 'Path') if element is not None else '' for element in ProcessObj_Image_Info]
    print('Lengths:', len(pid_list), len(name_list), len(parent_pid_list), len(path_list))

    print('columns =', ['file_name', 'PID', 'Name', 'Parent_PID', 'Path'])
    df = pd.DataFrame({'file_name': file.replace('.xml', ''), 'PID': pid_list,
                       'Name': name_list, 'Parent_PID': parent_pid_list, 'Path': path_list})
    
    # kyr, csv 저장 방식 수정
    if (file == "04ad737a6336.xml"):
        df.to_csv('IoC_dataset.csv')

    else:
        df.to_csv(r"IoC_dataset.csv", mode='a', header=False, index=False)
    print(df.head())

    #break  # '04ad737a6336.xml' 문서만 테스트
