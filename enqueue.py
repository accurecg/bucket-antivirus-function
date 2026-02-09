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
from urllib.parse import unquote_plus

import boto3

from common import AV_EXPECTED_BUCKET_KEY
from common import AV_SCAN_QUEUE_URL


def lambda_handler(event, context):
    if not AV_SCAN_QUEUE_URL:
        raise RuntimeError("AV_SCAN_QUEUE_URL is not set")

    sqs = boto3.client("sqs")
    records = event.get("Records") or []

    # SNS-wrapped S3 events: unwrap if needed
    if records and "Sns" in records[0]:
        event = json.loads(records[0]["Sns"]["Message"])
        records = event.get("Records") or []

    enqueued = 0
    for record in records:
        s3_info = record.get("s3") or {}
        bucket = (s3_info.get("bucket") or {}).get("name")
        key = (s3_info.get("object") or {}).get("key")
        if not bucket or not key:
            continue
        key = unquote_plus(key)

        # Only enqueue keys that match the ECG pattern
        if AV_EXPECTED_BUCKET_KEY and AV_EXPECTED_BUCKET_KEY not in key:
            continue

        body = {"bucket": bucket, "key": key}
        version_id = (s3_info.get("object") or {}).get("versionId")
        if version_id:
            body["versionId"] = version_id

        sqs.send_message(
            QueueUrl=AV_SCAN_QUEUE_URL,
            MessageBody=json.dumps(body),
        )
        enqueued += 1

    return {"enqueued": enqueued}
