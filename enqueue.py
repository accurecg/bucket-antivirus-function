# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Producer Lambda: receives S3 object create events, enqueues only keys that match
the ECG pattern (e.g. contain AV_EXPECTED_BUCKET_KEY or /ecgfile/) so the
queue and ECS workers only process scan-worthy objects.
"""

import json
import os
import hmac
import hashlib
import datetime
import urllib.request
import urllib.parse
from urllib.parse import unquote_plus

# Constants from environment
QUEUE_URL = os.environ.get("AV_SCAN_QUEUE_URL")
EXPECTED_KEY = os.environ.get("AV_EXPECTED_BUCKET_KEY")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def lambda_handler(event, context):
    records = event.get("Records") or []
    # SNS Unwrap
    if records and "Sns" in records[0]:
        event = json.loads(records[0]["Sns"]["Message"])
        records = event.get("Records") or []

    enqueued = 0
    for record in records:
        s3 = record.get("s3", {})
        bucket = s3.get("bucket", {}).get("name")
        key = unquote_plus(s3.get("object", {}).get("key", ""))

        if not bucket or not key or (EXPECTED_KEY and EXPECTED_KEY not in key):
            continue

        body = {"bucket": bucket, "key": key}
        if s3.get("object", {}).get("versionId"):
            body["versionId"] = s3["object"]["versionId"]

        send_sqs_raw(json.dumps(body))
        enqueued += 1

    return {"enqueued": enqueued}


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, "aws4_request")
    return k_signing


def send_sqs_raw(message_body):
    """Sends SQS message using raw HTTP POST (No Boto3)"""
    method = "POST"
    service = "sqs"
    host = f"sqs.{REGION}.amazonaws.com"
    endpoint = QUEUE_URL

    # Get credentials from Lambda environment
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("AWS_SESSION_TOKEN")

    t = datetime.datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    # Create payload (SQS Query API format)
    params = {
        "Action": "SendMessage",
        "Version": "2012-11-05",
        "MessageBody": message_body,
    }
    request_parameters = urllib.parse.urlencode(params)

    # SigV4 Signing Logic
    canonical_uri = "/" + "/".join(QUEUE_URL.split("/")[3:])
    canonical_querystring = ""
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    if token:
        canonical_headers += f"x-amz-security-token:{token}\n"

    signed_headers = "host;x-amz-date"
    if token:
        signed_headers += ";x-amz-security-token"

    payload_hash = hashlib.sha256(request_parameters.encode("utf-8")).hexdigest()
    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{REGION}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    signing_key = get_signature_key(secret_key, date_stamp, REGION, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    headers = {
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if token:
        headers["x-amz-security-token"] = token

    req = urllib.request.Request(
        endpoint, data=request_parameters.encode("utf-8"), headers=headers
    )
    with urllib.request.urlopen(req) as response:
        return response.read()
