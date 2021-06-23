#!/usr/local/bin//python3

'''

This python script connects to an infoblox DNS instance and queries all records.


Justin Garcia 24361 | 6/22/2021

'''

# Debugging assistance
from pprint import pprint
import re
import argparse
import pandas
import urllib3

# Load additional
from dotenv import load_dotenv
from dotenv.main import dotenv_values
from infoblox_client import connector
from infoblox_client import objects

# Set up arguments
arguments = argparse.ArgumentParser(description='''
This python script connects to an infoblox DNS instance and queries all records. It allows
you to search for specific records by hostname using regular expressions. It will then
return this data in a pandas dataframe. You can use the -d flag to trigger a delete
prompt for entries found through the -r flag.

''')
arguments.add_argument('dns_zone', action="store",
help="Specify DNS zone to act on"
)

arguments.add_argument('-r', '--regex', action="store",
default="((.*)(-mgmt)$)", dest="regex_string", help="Supports regex Default: (.*) [All]"
)

arguments.add_argument('-d', '--delete', action="store_true", dest='set_records_delete',
default=False, help="Prompt to delete records. Default: Print, don't prompt to delete"
)

arguments.add_argument('-f', '--found', action="store_true", dest='print_type_captured',
default=False, help="Specify to display only captured data with pandas. Default: False"
)

arguments.add_argument('-o', '--other', action="store_true", dest='print_type_other',
default=False, help="Specify to display only other data with pandas. Default: False"
)

arguments.add_argument('-c', '--create', action="store_true", dest='create_record',
default=False, help="Enable fake record creation. Default: False"
)

arguments.add_argument('-x', '--debug', action="store_true", dest='debug_flag',
default=False, help="Denable debug messages. Default: True"
)

# Supress urllib3 warnings and load dotenv for this script
urllib3.disable_warnings()
load_dotenv()

# Enable args
def main(_args):
    '''Main function'''

    conn = connector.Connector(dotenv_values())

    # Start kickoff
    try:

        start_records_manipulation(conn, args.dns_zone, args.regex_string, args.create_record,
         args.print_type_captured, args.print_type_other, args.set_records_delete
         )

    except SystemError as exception_message:
        print(exception_message)

def create_dummy_records(conn, dns_zone):
    '''Create new records in the infoblox zone'''
    try:

        objects.ARecord.create(
            conn,
            name=f"infoblox-mgmt.{dns_zone}",
            ip='10.0.0.114'
        )
        objects.ARecord.create(
            conn,
            name=f"infoblox-mgmt-server.{dns_zone}",
            ip='10.0.0.115'
        )
        objects.ARecord.create(
            conn,
            name=f"amunra-mgmt.{dns_zone}",
            ip='10.0.0.116'
        )
        objects.ARecord.create(
            conn,
            name=f"amunra-mgmt2.{dns_zone}",
            ip='10.0.0.117'
        )
        objects.AAAARecord.create(
            conn,
            name=f"amunra-mgmt.{dns_zone}",
            ip='a4f5:896c:4991:4795:9ca4:2abc:1ff5:e199'
        )
        objects.AAAARecord.create(
            conn,
            name=f"amunra-mgmt2.{dns_zone}",
            ip='68d3:00ca:896a:2f7b:9cd1:7a1f:a487:1c82'
        )
        objects.CNAMERecord.create(
            conn,
            name=f"CNAME-mgmt.{dns_zone}",
            canonical='10.0.0.118'
        )
        objects.TXTRecord.create(
            conn,
            name=f"TXTRECORD-mgmt.{dns_zone}",
            text='This is a test'
        )

    except Exception as exception_message:
        print(exception_message)

def collect_records(conn, dns_zone):
    ''' Find all records in database'''
    # Search entries
    all_records = objects.Allrecords.search_all(conn, zone=dns_zone)

    if DEBUG_FLAG is True:
        for record in all_records:
            #Print callable methods
            pprint(vars(record))

    return all_records

def sort_records(all_records, regex_string):
    '''Sort all records'''
    found_records = []
    other_records = []

    for record in all_records:

        record_fqdn = record.name + "." + record.zone

        try:
            if re.search(r'' + regex_string, str(record.name)):
                found_records += [[record.name, record.zone, record.type, record_fqdn, record.ref]]

            else:
                other_records += [[record.name, record.zone, record.type, record_fqdn, record.ref]]

        except SystemError as exception_message:
            print(exception_message)

    return found_records, other_records

def delete_records(conn, all_records, regex_string):
    '''Delete entries'''
    print("Sanity check! Printing vars(record)")
    for record in all_records:
        fqdn = record.name + "." + record.zone

        if DEBUG_FLAG is True:
            # Print callable methods
            pprint(vars(record))
            print("=====++++++++---------- Sanity check! ---------+++++++======")

        if re.search(r'' + regex_string, str(record.name)):
            print(f"SANITY CHECK: Trying to delete {fqdn}")
            if (record.type) == "record:a":
                try:
                    arecord = objects.ARecord.search(conn, name=fqdn, ref=record.ref)
                    arecord.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:aaaa":
                try:
                    aaaarecord = objects.AAAARecord.search(conn, name=fqdn, ref=record.ref)
                    aaaarecord.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:cname":
                try:
                    cnamerecord = objects.CNAMERecord.search(conn, name=fqdn, ref=record.ref)
                    cnamerecord.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:txt":
                try:
                    txtrecord = objects.TXTRecord.search(conn, name=fqdn, ref=record.ref)
                    txtrecord.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:mx":
                try:
                    mxrecord = objects.MXRecord.search(conn, name=fqdn, ref=record.ref)
                    mxrecord.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:host_ipv4addr":
                try:
                    hostv4record = objects.HostRecord.search(conn, name=fqdn, ref=record.ref)
                    hostv4record.delete()

                except SystemError as exception_message:
                    print(exception_message)

            if (record.type) == "record:host_ipv6addr":
                try:
                    hostv6record = objects.HostRecord.search(conn, name=fqdn, ref=record.ref)
                    hostv6record.delete()

                except SystemError as exception_message:
                    print(exception_message)

def print_all_records(found_records, other_records):
    '''Print all records'''

    # Print other records
    print("======-------------OTHER RECORDS-------------=====")
    other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])

    if DEBUG_FLAG:
        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
    else:
        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
    print("======---------------------------------------=====")

    # Gaps
    print("\n")

    # Print mgmt records
    print("======------------CAPTURED RECORDS-----------=====")
    found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
    if DEBUG_FLAG:
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
    else:
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
    print("======---------------------------------------=====")

def print_captured_records(found_records):
    '''Print mgmt records'''
    # Print mgmt records
    print("======------------CAPTURED RECORDS-----------=====")
    found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
    if DEBUG_FLAG:
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
    else:
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
    print("======---------------------------------------=====")

def print_other_records(other_records):
    '''Print other records'''
    # Print other records
    print("======-------------OTHER RECORDS-------------=====")
    other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
    if DEBUG_FLAG:
        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
    else:
        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

def start_records_manipulation(conn, dns_zone, regex_string, create_record,
    print_type_captured, print_type_other, set_records_delete
    ):
    '''Manipulation function'''
    # Prompt to create dummy records
    try:

        if eval(str(create_record)) is True:
            print("Proceeding to create records")

            try:
                create_dummy_records(conn, dns_zone)
                records_print(conn, dns_zone, regex_string, print_type_captured,
                    print_type_other, set_records_delete
                    )

            except SystemError as exception_message:
                print(exception_message)

        elif eval(str(create_record)) is False:
            try:
                print("Dummy creation skipped skipped.")
                records_print(conn, dns_zone, regex_string, print_type_captured,
                    print_type_other, set_records_delete
                    )

            except SystemError as exception_message:
                print(exception_message)

    except SystemError as exception_message:
        print(exception_message)

    try:
        if set_records_delete is True:

            all_records = collect_records(conn, dns_zone)
            print("=====0000 WARNING 0000====")
            input("  Press enter to continue with deletion (CTRL+C to cancel)")
            
            try:
                delete_records(conn, all_records, regex_string)
                records_print(conn, dns_zone, regex_string, print_type_captured,
                    print_type_other, set_records_delete
                    )

            except SystemError as exception_message:
                print(exception_message)

        elif set_records_delete is False:

            try:
                exit()

            except SystemError as exception_message:
                print(exception_message)

    except SystemError as exception_message:
        print(exception_message)

def records_print(conn, dns_zone, regex_string, print_type_captured,
    print_type_other, set_records_delete
    ):
    '''Orchestrates printing'''

    # Collect records and sort them
    sorted_records = sort_records(collect_records(conn, dns_zone), regex_string)

    try:
        # If all defaults, print all records
        if (print_type_captured is False and print_type_other is False
            and set_records_delete is False
            ):
            print_captured_records(sorted_records[0])

        # If only the -c flag is set, print captured records
        elif (print_type_captured is False and print_type_other is False
            and set_records_delete is True
            ):
            print_all_records(sorted_records[0], sorted_records[1])

        # If only the -c flag is set, print captured records
        elif (print_type_captured is True and print_type_other is False
            and set_records_delete is False
            ):
            print_captured_records(sorted_records[0])

        # If only the -i flag is set, print other records
        elif (print_type_captured is False and print_type_other is True
            and set_records_delete is False
            ):
            print_other_records(sorted_records[0])

    except SystemError as exception_message:
        print(exception_message)

# Call main function

if __name__ == '__main__':

    try:
        args = arguments.parse_args()
        global DEBUG_FLAG
        DEBUG_FLAG = args.debug_flag
        main(args)

    except SystemError as exception_message:
        print(exception_message)
