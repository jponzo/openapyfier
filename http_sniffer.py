from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
import json
import argparse


def sniff_packets(iface=None):
    """Sniff 80 port packets with `iface`, if None (default)."""
    if iface:
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter="port 80", prn=process_packet, store=False)


def process_packet(packet):
    """Process packet sniffed."""
    req = {
        "method": None,
        "uri": None,
        "body": None,
        "headers": {}
    }

    if packet.haslayer(HTTPRequest):
        req['uri'] = packet[HTTPRequest].Path.decode()
        req['method'] = packet[HTTPRequest].Method.decode()

        if packet.haslayer(Raw):
            req['body'] = json.loads(packet[Raw].load.decode("UTF-8"))
            if packet[HTTPRequest].Content_Type:
                req['headers']['content-type'] = packet[HTTPRequest].Content_Type.decode("UTF-8")
            if str(packet[HTTPRequest].Authorization):
                req['headers']['Authorization'] = "***HIDDEN***"
            for k in packet[HTTPRequest].Unknown_Headers.keys():
                req['headers'][k.decode("UTF-8")] = packet[HTTPRequest].Unknown_Headers[k].decode("UTF-8")

        print(json.dumps(req, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", help="Interface to use")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface

    sniff_packets(iface)


# {
#   "swagger": "2.0",
#   "info": {
#     "title": "Simple API overview",
#     "version": "v2"
#   },
#   "paths": {
#     "/": {
#       "get": {
#         "operationId": "listVersionsv2",
#         "summary": "List API versions",
#         "produces": [
#           "application/json"
#         ],
#         "responses": {
#           "200": {
#             "description": "200 300 response",
#             "examples": {
#               "application/json": "{\n    \"versions\": [\n        {\n            \"status\": \"CURRENT\",\n            \"updated\": \"2011-01-21T11:33:21Z\",\n            \"id\": \"v2.0\",\n            \"links\": [\n                {\n                    \"href\": \"http://127.0.0.1:8774/v2/\",\n                    \"rel\": \"self\"\n                }\n            ]\n        },\n        {\n            \"status\": \"EXPERIMENTAL\",\n            \"updated\": \"2013-07-23T11:33:21Z\",\n            \"id\": \"v3.0\",\n            \"links\": [\n                {\n                    \"href\": \"http://127.0.0.1:8774/v3/\",\n                    \"rel\": \"self\"\n                }\n            ]\n        }\n    ]\n}"
#             }
#           },
#           "300": {
#             "description": "200 300 response",
#             "examples": {
#               "application/json": "{\n    \"versions\": [\n        {\n            \"status\": \"CURRENT\",\n            \"updated\": \"2011-01-21T11:33:21Z\",\n            \"id\": \"v2.0\",\n            \"links\": [\n                {\n                    \"href\": \"http://127.0.0.1:8774/v2/\",\n                    \"rel\": \"self\"\n                }\n            ]\n        },\n        {\n            \"status\": \"EXPERIMENTAL\",\n            \"updated\": \"2013-07-23T11:33:21Z\",\n            \"id\": \"v3.0\",\n            \"links\": [\n                {\n                    \"href\": \"http://127.0.0.1:8774/v3/\",\n                    \"rel\": \"self\"\n                }\n            ]\n        }\n    ]\n}"
#             }
#           }
#         }
#       }
#     },
#     "/v2": {
#       "get": {
#         "operationId": "getVersionDetailsv2",
#         "summary": "Show API version details",
#         "produces": [
#           "application/json"
#         ],
#         "responses": {
#           "200": {
#             "description": "200 203 response",
#             "examples": {
#               "application/json": "{\n    \"version\": {\n        \"status\": \"CURRENT\",\n        \"updated\": \"2011-01-21T11:33:21Z\",\n        \"media-types\": [\n            {\n                \"base\": \"application/xml\",\n                \"type\": \"application/vnd.openstack.compute+xml;version=2\"\n            },\n            {\n                \"base\": \"application/json\",\n                \"type\": \"application/vnd.openstack.compute+json;version=2\"\n            }\n        ],\n        \"id\": \"v2.0\",\n        \"links\": [\n            {\n                \"href\": \"http://127.0.0.1:8774/v2/\",\n                \"rel\": \"self\"\n            },\n            {\n                \"href\": \"http://docs.openstack.org/api/openstack-compute/2/os-compute-devguide-2.pdf\",\n                \"type\": \"application/pdf\",\n                \"rel\": \"describedby\"\n            },\n            {\n                \"href\": \"http://docs.openstack.org/api/openstack-compute/2/wadl/os-compute-2.wadl\",\n                \"type\": \"application/vnd.sun.wadl+xml\",\n                \"rel\": \"describedby\"\n            },\n            {\n              \"href\": \"http://docs.openstack.org/api/openstack-compute/2/wadl/os-compute-2.wadl\",\n              \"type\": \"application/vnd.sun.wadl+xml\",\n              \"rel\": \"describedby\"\n            }\n        ]\n    }\n}"
#             }
#           },
#           "203": {
#             "description": "200 203 response",
#             "examples": {
#               "application/json": "{\n    \"version\": {\n        \"status\": \"CURRENT\",\n        \"updated\": \"2011-01-21T11:33:21Z\",\n        \"media-types\": [\n            {\n                \"base\": \"application/xml\",\n                \"type\": \"application/vnd.openstack.compute+xml;version=2\"\n            },\n            {\n                \"base\": \"application/json\",\n                \"type\": \"application/vnd.openstack.compute+json;version=2\"\n            }\n        ],\n        \"id\": \"v2.0\",\n        \"links\": [\n            {\n                \"href\": \"http://23.253.228.211:8774/v2/\",\n                \"rel\": \"self\"\n            },\n            {\n                \"href\": \"http://docs.openstack.org/api/openstack-compute/2/os-compute-devguide-2.pdf\",\n                \"type\": \"application/pdf\",\n                \"rel\": \"describedby\"\n            },\n            {\n                \"href\": \"http://docs.openstack.org/api/openstack-compute/2/wadl/os-compute-2.wadl\",\n                \"type\": \"application/vnd.sun.wadl+xml\",\n                \"rel\": \"describedby\"\n            }\n        ]\n    }\n}"
#             }
#           }
#         }
#       }
#     }
#   },
#   "consumes": [
#     "application/json"
#   ]
# }
