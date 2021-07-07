#!/usr/local/bin//python3

'''
This python script connects to an infoblox DNS instance and queries all records.


Justin Garcia 24361 | 6/22/2021

'''

#
import getpass

#
import argparse
import urllib3

# Load additional
from infoblox_client import connector

# Set up arguments
arguments = argparse.ArgumentParser(description='''
This python script connects to an infoblox DNS instance and queries all records. It allows
you to search for specific records by hostname using regular expressions. You can use the -d 
flag to trigger a delete prompt for entries found.

''')

arguments.add_argument('search_string', action="store", nargs='?',
default="all", help="Hostname to search for")


arguments.add_argument('-r', '--regex', action="store_true", dest="regex",
default=False, help="Enables regex support for hostname"
)

arguments.add_argument('-d', '--delete', action="store_true", dest='set_records_delete',
default=False, help="Prompt to delete records. Default: Print, don't prompt to delete"
)


# Supress urllib3 warnings and load dotenv for this script
urllib3.disable_warnings()

# Enable args
def main(_args):
    '''Main function'''
    try:
        user = input("Infoblox username: ")
        password = getpass.getpass("Infoblox password: ")
        opts = {'host': "10.0.0.100", 'username': user, 'password': password}
        
        try:
            conn = connector.Connector(opts)
        
        except SystemError as exception_message:
            print(exception_message)
            exit()

    except SystemError as exception_message:
        print(exception_message)
        exit()

    # Collect records
    try:
        records = collect_records(conn, args.search_string, args.regex)

    except SystemError as exception_message:
        print(exception_message)

    # Print records
    try:
        print_records(records)

    except SystemError as exception_message:
        print(exception_message)

def collect_records(conn, search_string, regex):
    ''' Find all records in database'''
    # Search entries
    records = []

    search_type = 'name'

    if regex is True:
        search_type = 'name~'

    # Check if we are searching by regex
    for record_type in ['a', 'aaaa', 'txt', 'host', 'cname']:
        try:
            record = conn.get_object(f"record:{record_type}", {search_type: search_string})
            
            if record is not None:
                for item in record:
                    records.append(item['_ref'])
            else:
                print(f"No {record_type} records found for {search_string}")

        except Exception as exception_message:
            print(exception_message)

    return records


def delete_records(conn, records):

    for record in records:
        if record is not None or " ":
            print(f"attempting to delete: {record}")
            conn.delete_object(record)

def print_records(records):
    '''Print all records'''

    # Print found
    print("======-------------------CAPTURED RECORDS------------------=====")
    for record in records:
        print(record)
    print("======-----------------------------------------------------=====")

# Call main function

if __name__ == '__main__':
    try:
        args = arguments.parse_args()
        main(args)

    except SystemError as exception_message:
        print(exception_message)