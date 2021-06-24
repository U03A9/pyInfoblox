#!/usr/local/bin//python3

'''
This python script connects to an infoblox DNS instance and queries all records.


Justin Garcia 24361 | 6/22/2021

'''

# Debugging assistance
from pprint import pprint
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

arguments.add_argument('record_type', action="store",
help="Record type to search. Default: All"
)

arguments.add_argument('search_string', action="store", nargs='?',
default="all", help="Hostname to search for")


arguments.add_argument('-r', '--regex', action="store_true", dest="regex_search",
default=False, help="Enables regex support for hostname"
)

arguments.add_argument('-d', '--delete', action="store_true", dest='set_records_delete',
default=False, help="Prompt to delete records. Default: Print, don't prompt to delete"
)

arguments.add_argument('-c', '--create', action="store_true", dest='create_record',
default=False, help="Enable fake record creation. Specify zone with -z or --zone Default: False"
)

arguments.add_argument('-z', '--zone', action="store", nargs='?',
dest="dns_zone", default="thenile.gemstatecyber.com", help="Specify DNS zone to act on. Only works with create flag"
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
    try:

        conn = connector.Connector(dotenv_values())

    except SystemError as exception_message:
        pprint(exception_message)

    try:
        records = collect_records(conn, args.record_type,
         args.search_string, args.regex_search)

    except SystemError as exception_message:
        pprint(exception_message)

    # Start kickoff
    try:

        start_records_manipulation(conn, args.dns_zone, args.record_type,
         args.search_string, args.create_record, records, args.set_records_delete,
         args.regex_search
         )

    except SystemError as exception_message:
        pprint(exception_message)

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
        pprint(exception_message)

def collect_records(conn, record_type, search_string, regex_search):
    ''' Find all records in database'''
    # Search entries
    records = []

    if search_string in ['All', 'all', '', ' ']:
        search_string = "(.*)"
    if record_type in ['All', 'all']:
        for record_type in ['a', 'aaaa', 'txt', 'host']:
            if regex_search:
                try:
                    record = conn.get_object(f"record:{(record_type).lower()}", {'name~': search_string})

                    if record is not None:
                        records += record

                except Exception as exception_message:
                    pprint(exception_message)

            else:
                if search_string == "(.*)":
                    try:
                        record = conn.get_object(f"record:{(record_type).lower()}", {'name~': search_string})

                        if record is not None:
                            records += record

                    except Exception as exception_message:
                        pprint(exception_message)

                else:
                    try:
                        record = conn.get_object(f"record:{(record_type).lower()}", {'name': search_string})

                        if record is not None:
                            records += record

                    except Exception as exception_message:
                        pprint(exception_message)
        
    else:
        try:
            record = conn.get_object(f"record:{(record_type).lower()}", {'name~': search_string})

            if record is not None:
                records += record

        except Exception as exception_message:
            pprint(exception_message)

    if records is None:
        print("No records found for record search parameters")

    else:
        try:
            if XDEBUG_FLAG:
                pprint(records)
                return records

            elif SDEBUG_FLAG:
                print(f"Records collection initiated\n\trecord_type: {(record_type).lower()}\n\tsearch_string: {search_string}\n\tregex_search_flag: {regex_search}")
                pprint(records)
                return records

            else:
                return records

        except SystemError as exception_message:
            pprint(exception_message)

def delete_records(conn, records):
    '''Delete entries'''
    for record in records:

        fqdn = record['name']
        ref = (record['_ref'])
        record_type = ((record['_ref']).split("/")[0])

        if SDEBUG_FLAG:
            print(f"SEARCHING FOR RECORD:\n\tName: {fqdn}\n\tRef: {ref}\n\tType: {(record_type).lower()}")
            pprint(record)

        if XDEBUG_FLAG:
            print(f"SEARCHING FOR RECORD:\n\tName: {fqdn}\n\tRef: {ref}\n\tType: {(record_type).lower()}")

        if record_type == "record:a":
            try:
                arecord = objects.ARecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(f"Trying to delete {fqdn}\n\ttype: {type(arecord)}\n\tref: {ref}")
                
                elif SDEBUG_FLAG is True:
                    pprint(f"Trying to delete {fqdn}\n\ttype: {type(arecord)}\n\tref: {ref}")
                
                else:
                    arecord.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:aaaa":
            try:
                aaaarecord = objects.AAAARecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(aaaarecord)
                    pprint(f"Trying to delete {record['name']}")
                
                elif SDEBUG_FLAG is True:
                    pprint(aaaarecord)
                    pprint(f"Trying to delete {record['name']}")

                aaaarecord.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:cname":
            try:
                cnamerecord = objects.CNAMERecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(cnamerecord)
                    pprint(f"Trying to delete {record['name']}")

                elif SDEBUG_FLAG is True:
                    pprint(cnamerecord)
                    pprint(f"Trying to delete {record['name']}")

                cnamerecord.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:txt":
            try:
                txtrecord = objects.TXTRecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(txtrecord)
                    pprint(f"Trying to delete {record['name']}")

                elif SDEBUG_FLAG is True:
                    pprint(txtrecord)
                    pprint(f"Trying to delete {record['name']}")

                txtrecord.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:mx":
            try:
                mxrecord = objects.MXRecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(mxrecord)
                    pprint(f"Trying to delete {record['name']}")

                elif SDEBUG_FLAG is True:
                    pprint(mxrecord)
                    pprint(f"Trying to delete {record['name']}")

                mxrecord.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:host_ipv4addr":
            try:
                hostv4record = objects.HostRecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(vars(hostv4record))
                    pprint(f"Trying to delete {record['name']}")

                elif SDEBUG_FLAG is True:
                    pprint(vars(hostv4record))
                    pprint(f"Trying to delete {record['name']}")

                hostv4record.delete()

            except SystemError as exception_message:
                pprint(exception_message)

        if record_type == "record:host_ipv6addr":
            try:
                hostv6record = objects.HostRecord.search(conn, name=fqdn)

                if XDEBUG_FLAG is True:
                    pprint(hostv6record)
                    pprint(f"Trying to delete {record['name']}")

                elif SDEBUG_FLAG is True:
                    pprint(hostv6record)
                    pprint(f"Trying to delete {record['name']}")

                hostv6record.delete()

            except SystemError as exception_message:
                pprint(exception_message)

def print_records(records):
    '''Print all records'''

    if XDEBUG_FLAG:
        # Print found
        print("======-------------------CAPTURED RECORDS------------------=====")
        print((pandas.DataFrame(records)).to_string(index=False, max_colwidth=40, justify="left"))
        print("======-----------------------------------------------------=====")
    
    elif SDEBUG_FLAG:
        print("Super Debugging Enabled: Pandas dataframe printing disabled.")

        for record in records:
            #Print callable methods
            pprint(record)

    else:
        # Print found records
        print("======-------------------CAPTURED RECORDS------------------=====")
        print((pandas.DataFrame(records)).to_string(index=False, max_colwidth=40, justify="left"))
        print("======-----------------------------------------------------=====")

def start_records_manipulation(conn, dns_zone, record_type, search_string, create_record,
     records, set_records_delete, regex_search
    ):
    '''Manipulation function'''
    # Prompt to create dummy records
    try:
        if create_record is True:
            pprint("Proceeding to create records")

            try:
                create_dummy_records(conn, dns_zone)
                print_records(records)

            except SystemError as exception_message:
                pprint(exception_message)

        else:
            try:
                print_records(records)

            except SystemError as exception_message:
                pprint(exception_message)

    except SystemError as exception_message:
        pprint(exception_message)

    try:
        if set_records_delete is True:
            input("Press enter to continue with deletion (CTRL+C to cancel)")
            
            try:
                delete_records(conn, (collect_records(conn, record_type, search_string, regex_search)))
                print_records((collect_records(conn, record_type, search_string, regex_search)))

            except SystemError as exception_message:
                pprint(exception_message)

    except SystemError as exception_message:
        pprint(exception_message)

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
        pprint(exception_message)