import pyfpgrowth
import pandas as pd


def get_result(data):
    # Get the association rules
    patterns = pyfpgrowth.find_frequent_patterns(data.values, 2)
    rules = pyfpgrowth.generate_association_rules(patterns, 0.8)

    # Print if a result value is greater than 2
    for key in rules:
        if rules[key][1] > 1.0:
            print('Rule')
            print(key, '->', rules[key])
            print()


def association_address():
    # Get an association rule from the column "Address"
    address = duplicated_data[['Address', 'family']].dropna()
    address['value_1'] = address.Address.str.split('.').str[0]
    address['value_2'] = address.Address.str.split('.').str[1]
    address['value_3'] = address.Address.str.split('.').str[2]
    address['value_4'] = address.Address.str.split('.').str[3]
    address = address.drop(['Address'], axis=1).dropna()

    get_result(address)


def association_dns():
    # Get an association rule from the column "DNS"
    dns = duplicated_data[['DNS', 'family']].dropna()
    dns['value_1'] = dns.DNS.str.split('.').str[0]
    dns['value_2'] = dns.DNS.str.split('.').str[1]
    dns['value_3'] = dns.DNS.str.split('.').str[2]
    dns = dns.drop(['DNS'], axis=1).dropna()

    get_result(dns)


def association_process_name():
    # Get a association rule from the column "Process_Name"
    process_name = duplicated_data[['Process_Name', 'family']]
    process_name = process_name.dropna()

    get_result(process_name)


def association_process_path():
    # Get a association rule from the column "Process_Path"
    process_path = duplicated_data[['Process_Path', 'family']].dropna()
    process_path['value_1'] = process_path.Process_Path.str.split('\\').str[1]
    process_path['value_2'] = process_path.Process_Path.str.split('\\').str[2]
    process_path['value_3'] = process_path.Process_Path.str.split('\\').str[3]
    process_path['value_4'] = process_path.Process_Path.str.split('\\').str[4]
    process_path['value_5'] = process_path.Process_Path.str.split('\\').str[5]
    process_path = process_path.drop(['Process_Path'], axis=1).dropna()

    get_result(process_path)


def association_file_name():
    # Get a association rule from the column "File_Name"
    file_name = duplicated_data[['File_Name', 'family']].dropna()
    file_name['value_1'] = file_name.File_Name.str.split('\\').str[0]
    file_name['value_2'] = file_name.File_Name.str.split('\\').str[1]
    file_name['value_3'] = file_name.File_Name.str.split('\\').str[2]
    file_name['value_4'] = file_name.File_Name.str.split('\\').str[3]
    file_name['value_5'] = file_name.File_Name.str.split('\\').str[4]
    file_name['value_6'] = file_name.File_Name.str.split('\\').str[5]
    file_name['value_7'] = file_name.File_Name.str.split('\\').str[6]
    file_name = file_name.drop(['File_Name'], axis=1).dropna()

    get_result(file_name)


def association_file_path():
    # Get a association rule from the column "File_Path"
    file_path = duplicated_data[['File_Path', 'family']].dropna()
    file_path['value_1'] = file_path.File_Path.str.split('\\').str[1]
    file_path['value_2'] = file_path.File_Path.str.split('\\').str[2]
    file_path['value_3'] = file_path.File_Path.str.split('\\').str[3]
    file_path['value_4'] = file_path.File_Path.str.split('\\').str[4]
    file_path['value_5'] = file_path.File_Path.str.split('\\').str[5]
    file_path['value_6'] = file_path.File_Path.str.split('\\').str[6]
    file_path['value_7'] = file_path.File_Path.str.split('\\').str[7]
    file_path = file_path.drop(['File_Path'], axis=1).dropna()

    get_result(file_path)


# Bring both refined and duplicated data
iocData = pd.read_csv('IoC_dataset.csv')
duplicated_data = pd.read_csv('Duplicated_dataset.csv')

# Get a malware family names list
family_list = iocData['family'].unique()

print('[Address] association rules')
association_address()
print('[DNS] association rules')
association_dns()
print('[Process_Name] association rules')
association_process_name()
print('[Process_Path] association rules')
association_process_path()
print('[File_Name] association rules')
association_file_name()
print('[File_Path] association rules')
association_file_path()
