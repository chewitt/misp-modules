"""
Export MISP events as a CSV formatted IP feed for Fidelis CommandPost
"""

import base64
import csv
import io
import json
import logging


misperrors = {"error": "Error"}

moduleinfo = {
    "version": "1.0",
    "author": "Christian Hewitt, Fidelis Cybersecurity",
    "description": "Export MISP events as a CSV formatted IP feed for Fidelis CommandPost",
    "module-type": ["export"]
}

moduleconfig = []

# Map MISP attributes to Fidelis IP feed attributes
fieldmap = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "port": "port",
    "hostname": "hostname",
    "info": "extra_info"
}

# Combine MISP fields from fieldmap into one big list
mispattributes = {
    "input": list(fieldmap.keys())
}


def handler(q=False):
    if q is False or not q:
        return False

    request = json.loads(q)

    response = io.StringIO()
    writer = csv.DictWriter(response, fieldnames=["value"])
    writer.writeheader()

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                logging.debug("Adding %s to CSV formatted IP feed for Fidelis CommandPost", attribute["value"])
                writer.writerow({
                    "value": attribute["value"]
                })

    return {"response": [], "data": str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}


def introspection():
    modulesetup = {
        "responseType": "application/txt",
        "outputFileExtension": "csv",
        "userConfig": {},
        "inputSource": []
    }
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
