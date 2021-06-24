import getpass
from infoblox_client import connector
import urllib3

# Disable urllib3 warnings

urllib3.disable_warnings()


password = getpass.getpass()
opts = {'host': "10.0.0.100", 'username': 'admin', 'password': password, 'http_request_timeout': 60}
conn = connector.Connector(opts)
search_string = input("Provide a host to search for. Regex is supported: ")
records = []

for record_type in ['a', 'aaaa', 'txt', 'host']:
    record = conn.get_object(f"record:{record_type}", {'name~': search_string})

    if record is not None:
        records += record

print(records)
print(len(records))
