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

# Set pandas options
pandas.set_option('display.max_colwidth', 500)
pandas.set_option('display.max_columns', 0)


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
default="((.*))", dest="regex_string", help="Supports regex Default: (.*) [All]"
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

arguments.add_argument('-s', '--superdebug', action="store_true", dest='sdebug_flag',
default=False, help="Enable debug messages. Default: True"
)

arguments.add_argument('-x', '--debug', action="store_true", dest='xdebug_flag',
default=False, help="Enable more debug messages. Default: True"
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

def delete_records(conn, found_records, regex_string):
    '''Delete entries'''
    for record in found_records:

        if SDEBUG_FLAG:
            #print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
            print("XDebug enabled. Skipping printing panda record.")
            for record in records:
                print("Record for deletion")
                print(record)

        record_type = record[2]
        record_fqdn = record[3]
        record_ref = record[4]

        if (record_type) == "record:a":
            try:
                arecord = objects.ARecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(arecord))
                    print(f"Trying to delete {record_fqdn}")

                arecord.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:aaaa":
            try:
                aaaarecord = objects.AAAARecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(aaaarecord))
                    print(f"Trying to delete {record_fqdn}")

                aaaarecord.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:cname":
            try:
                cnamerecord = objects.CNAMERecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(cnamerecord))
                    print(f"Trying to delete {record_fqdn}")


                cnamerecord.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:txt":
            try:
                txtrecord = objects.TXTRecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(txtrecord))
                    print(f"Trying to delete {record_fqdn}")

                txtrecord.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:mx":
            try:
                mxrecord = objects.MXRecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(mxrecord))
                    print(f"Trying to delete {record_fqdn}")

                mxrecord.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:host_ipv4addr":
            try:
                hostv4record = objects.HostRecord.search(conn, name=record_fqdn, ref=record_ref)

                if XDEBUG_FLAG is True:
                    pprint(vars(hostv4record))
                    print(f"Trying to delete {record_fqdn}")

                hostv4record.delete()

            except SystemError as exception_message:
                print(exception_message)

        if (record_type) == "record:host_ipv6addr":
            try:
                hostv6record = objects.HostRecord.search(conn, name=record_fqdn, ref=record_ref)
                
                if XDEBUG_FLAG is True:
                    pprint(vars(hostv6record))
                    print(f"Trying to delete {record_fqdn}")

                hostv6record.delete()

            except SystemError as exception_message:
                print(exception_message)

def print_all_records(found_records, other_records):
    '''Print all records'''

    if XDEBUG_FLAG:
        # Print other records
        print("======-------------OTHER RECORDS-------------=====")
        other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])

        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

        # Gaps
        print("\n")

        # Print mgmt records
        print("======------------CAPTURED RECORDS-----------=====")
        found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")
    
    elif SDEBUG_FLAG:
        #print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
        print("XDebug enabled. Skipping printing panda record.")

        for record in found_records:
            #Print callable methods
            print(record)

    else:
        # Print other records
        print("======-------------OTHER RECORDS-------------=====")
        other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])

        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

        # Gaps
        print("\n")

        # Print mgmt records
        print("======------------CAPTURED RECORDS-----------=====")
        found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

def print_captured_records(found_records):
    '''Print mgmt records'''

    if XDEBUG_FLAG:
        # Print mgmt records
        print("======------------CAPTURED RECORDS-----------=====")
        found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

    elif SDEBUG_FLAG:
        #print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
        print("XDebug enabled. Skipping printing panda record.")

        for record in found_records:
            #Print callable methods
            print(record)
    else:
        # Print mgmt records
        print("======------------CAPTURED RECORDS-----------=====")
        found_records = pandas.DataFrame(found_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
        print((found_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

def print_other_records(other_records):
    '''Print other records'''

    if XDEBUG_FLAG:
        # Print other records
        print("======-------------OTHER RECORDS-------------=====")
        other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
        print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN']]).to_string(index=False))
        print("======---------------------------------------=====")

    elif SDEBUG_FLAG:
        #print((other_records[['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF']]).to_string(index=False))
        print("XDebug enabled. Skipping printing panda record.")

        for record in other_records:
            #Print callable methods
            pprint(vars(record))

    else:
        # Print other records
        print("======-------------OTHER RECORDS-------------=====")
        other_records = pandas.DataFrame(other_records, columns = ['NAME', 'ZONE', 'TYPE', 'FQDN', 'REF'])
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
            input("Press enter to continue with deletion (CTRL+C to cancel)")
            
            try:

                delete_records(conn, (sort_records(collect_records(conn, dns_zone), regex_string))[0], regex_string)
                records_print(conn, dns_zone, regex_string, print_type_captured,
                    print_type_other, set_records_delete
                    )

            except SystemError as exception_message:
                print(exception_message)

    except SystemError as exception_message:
        print(exception_message)

def records_print(conn, dns_zone, regex_string, print_type_captured,
    print_type_other, set_records_delete
    ):
    '''Orchestrates printing'''

    if XDEBUG_FLAG:
        print(f"Printing passed variables to function: records_print\n\tprint_type_captured: {print_type_captured}\n\tprint_type_other: {print_type_other}\n\tset_records_delete: {set_records_delete}")

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

        # If only the -c flag is set, print captured records
        elif (print_type_captured is True and print_type_other is False
            and set_records_delete is True
            ):
            print_captured_records(sorted_records[0])

        # If only the -i flag is set, print other records
        elif (print_type_captured is True and print_type_other is True
            and set_records_delete is True
            ):
            print_other_records(sorted_records[1])

        # If only the -c flag is set, print captured records
        elif (print_type_captured is False and print_type_other is False
            and set_records_delete is True
            ):
            print_captured_records(sorted_records[0])

        # If only the -i flag is set, print other records
        elif (print_type_captured is False and print_type_other is True
            and set_records_delete is False
            ):
            print_other_records(sorted_records[1])

        # If only the -i flag is set, print other records
        elif (print_type_captured is False and print_type_other is True
            and set_records_delete is True
            ):
            print_other_records(sorted_records[1])

    except SystemError as exception_message:
        print(exception_message)

# Call main function

if __name__ == '__main__':
    try:
        args = arguments.parse_args()
        global XDEBUG_FLAG
        XDEBUG_FLAG = args.xdebug_flag
        global SDEBUG_FLAG 
        SDEBUG_FLAG = args.sdebug_flag
        main(args)

    except SystemError as exception_message:
        print(exception_message)
