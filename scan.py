# -*- coding: utf-8 -*-
# Upside Travel, Inc.
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

import copy
import json
import os
import time
from urllib.parse import unquote_plus

import boto3

import clamav
import metrics
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_DELETE_INFECTED_FILES
from common import AV_PROCESS_ORIGINAL_VERSION_ONLY
from common import AV_SCAN_START_METADATA
from common import AV_SCAN_START_SNS_ARN
from common import AV_SCAN_BUCKET
from common import AV_SIGNATURE_METADATA
from common import AV_STATUS_CLEAN
from common import AV_STATUS_INFECTED
from common import AV_STATUS_METADATA
from common import AV_EXPECTED_BUCKET_KEY
from common import AV_EXPECTED_BUCKET_KEY_STATUS
from common import AV_STATUS_SNS_ARN
from common import AV_STATUS_SNS_PUBLISH_CLEAN
from common import AV_STATUS_SNS_PUBLISH_INFECTED
from common import AV_TIMESTAMP_METADATA
from common import create_dir
from common import get_timestamp


def event_object(event, event_source="s3"):

    # SNS events are slightly different
    if event_source.upper() == "SNS":
        event = json.loads(event["Records"][0]["Sns"]["Message"])

    # Break down the record
    records = event["Records"]
    if len(records) == 0:
        raise Exception("No records found in event!")
    record = records[0]

    s3_obj = record["s3"]

    # Get the bucket name
    if "bucket" not in s3_obj:
        raise Exception("No bucket found in event!")
    bucket_name = s3_obj["bucket"].get("name", None)

    # Get the key name
    if "object" not in s3_obj:
        raise Exception("No key found in event!")
    key_name = s3_obj["object"].get("key", None)

    if key_name:
        key_name = unquote_plus(key_name)

    # Ensure both bucket and key exist
    if (not bucket_name) or (not key_name):
        raise Exception("Unable to retrieve object from event.\n{}".format(event))

    # Create and return the object
    s3 = boto3.resource("s3")
    return s3.Object(bucket_name, key_name)


def verify_s3_object_version(s3, s3_object):
    # validate that we only process the original version of a file, if asked to do so
    # security check to disallow processing of a new (possibly infected) object version
    # while a clean initial version is getting processed
    # downstream services may consume latest version by mistake and get the infected version instead
    bucket_versioning = s3.BucketVersioning(s3_object.bucket_name)
    if bucket_versioning.status == "Enabled":
        bucket = s3.Bucket(s3_object.bucket_name)
        versions = list(bucket.object_versions.filter(Prefix=s3_object.key))
        if len(versions) > 1:
            raise Exception(
                "Detected multiple object versions in %s.%s, aborting processing"
                % (s3_object.bucket_name, s3_object.key)
            )
    else:
        # misconfigured bucket, left with no or suspended versioning
        raise Exception(
            "Object versioning is not enabled in bucket %s" % s3_object.bucket_name
        )


def get_local_path(s3_object, local_prefix):
    return os.path.join(local_prefix, s3_object.bucket_name, s3_object.key)


def delete_s3_object(s3_object):
    try:
        s3_object.delete()
    except Exception:
        raise Exception(
            "Failed to delete infected file: %s.%s"
            % (s3_object.bucket_name, s3_object.key)
        )
    else:
        print(
            "Infected file deleted: %s.%s" % (s3_object.bucket_name, s3_object.key),
            flush=True,
        )


def set_av_metadata(s3_object, scan_result, scan_signature, timestamp):
    content_type = s3_object.content_type
    metadata = s3_object.metadata
    metadata[AV_SIGNATURE_METADATA] = scan_signature
    metadata[AV_STATUS_METADATA] = scan_result
    metadata[AV_TIMESTAMP_METADATA] = timestamp
    s3_object.copy(
        {"Bucket": s3_object.bucket_name, "Key": s3_object.key},
        ExtraArgs={
            "ContentType": content_type,
            "Metadata": metadata,
            "MetadataDirective": "REPLACE",
        },
    )


def set_av_tags(s3_client, s3_object, scan_result, scan_signature, timestamp):
    curr_tags = s3_client.get_object_tagging(
        Bucket=s3_object.bucket_name, Key=s3_object.key
    )["TagSet"]
    new_tags = copy.copy(curr_tags)
    for tag in curr_tags:
        if tag["Key"] in [
            AV_SIGNATURE_METADATA,
            AV_STATUS_METADATA,
            AV_TIMESTAMP_METADATA,
        ]:
            new_tags.remove(tag)
    new_tags.append({"Key": AV_SIGNATURE_METADATA, "Value": scan_signature})
    new_tags.append({"Key": AV_STATUS_METADATA, "Value": scan_result})
    new_tags.append({"Key": AV_TIMESTAMP_METADATA, "Value": timestamp})
    s3_client.put_object_tagging(
        Bucket=s3_object.bucket_name, Key=s3_object.key, Tagging={"TagSet": new_tags}
    )


def sns_start_scan(sns_client, s3_object, scan_start_sns_arn, timestamp):
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_SCAN_START_METADATA: True,
        AV_TIMESTAMP_METADATA: timestamp,
    }
    sns_client.publish(
        TargetArn=scan_start_sns_arn,
        Message=json.dumps({"default": json.dumps(message)}),
        MessageStructure="json",
    )


def sns_scan_results(
    sns_client, s3_object, sns_arn, scan_result, scan_signature, timestamp
):
    # Don't publish if scan_result is CLEAN and CLEAN results should not be published
    if scan_result == AV_STATUS_CLEAN and not str_to_bool(AV_STATUS_SNS_PUBLISH_CLEAN):
        return
    # Don't publish if scan_result is INFECTED and INFECTED results should not be published
    if scan_result == AV_STATUS_INFECTED and not str_to_bool(
        AV_STATUS_SNS_PUBLISH_INFECTED
    ):
        return
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_SIGNATURE_METADATA: scan_signature,
        AV_STATUS_METADATA: scan_result,
        AV_TIMESTAMP_METADATA: get_timestamp(),
    }
    sns_client.publish(
        TargetArn=sns_arn,
        Message=json.dumps({"default": json.dumps(message)}),
        MessageStructure="json",
        MessageAttributes={
            AV_SCAN_BUCKET: {
                "DataType": "String",
                "StringValue": s3_object.bucket_name,
            },
            AV_STATUS_METADATA: {"DataType": "String", "StringValue": scan_result},
            AV_SIGNATURE_METADATA: {
                "DataType": "String",
                "StringValue": scan_signature,
            },
            AV_EXPECTED_BUCKET_KEY_STATUS: {
                "DataType": "String",
                "StringValue": "PRESENT"
                if AV_EXPECTED_BUCKET_KEY in s3_object.key
                else "NOT_PRESENT",
            },
        },
    )


def scan_one_object_from_path(
    s3_object,
    file_path,
    *,
    s3_resource=None,
    s3_client=None,
    sns_client=None,
    skip_post_processing=False,
):
    """
    Scan an already-downloaded file with ClamAV, set tags/metadata, publish SNS, send metrics.
    Used by the ECS worker prefetch pipeline; caller owns file_path and must os.remove it.
    Does not download; assumes file exists at file_path.
    When skip_post_processing=True, only runs the scan and optional set_av_metadata; the caller
    is responsible for S3 tagging, SNS publish, SQS delete (e.g. via worker.run_post_processing_tasks).
    Returns (scan_result, scan_signature).
    """
    s3 = s3_resource if s3_resource is not None else boto3.resource("s3")
    s3_client = s3_client if s3_client is not None else boto3.client("s3")
    sns_client = sns_client if sns_client is not None else boto3.client("sns")
    ENV = os.getenv("ENV", "")

    if str_to_bool(AV_PROCESS_ORIGINAL_VERSION_ONLY):
        verify_s3_object_version(s3, s3_object)

    if AV_SCAN_START_SNS_ARN not in [None, ""]:
        start_scan_time = get_timestamp()
        sns_start_scan(sns_client, s3_object, AV_SCAN_START_SNS_ARN, start_scan_time)

    s3_uri = "s3://%s/%s" % (s3_object.bucket_name, s3_object.key)
    print("Starting scan of %s (local path: %s)" % (s3_uri, file_path), flush=True)
    scan_start = time.time()
    scan_result, scan_signature = clamav.scan_file(file_path)
    scan_elapsed = time.time() - scan_start
    print(
        "Scan completed for %s in %.2f s - result: %s\n"
        % (s3_uri, scan_elapsed, scan_result),
        flush=True,
    )

    result_time = get_timestamp()
    if "AV_UPDATE_METADATA" in os.environ:
        set_av_metadata(s3_object, scan_result, scan_signature, result_time)

    if skip_post_processing:
        return scan_result, scan_signature

    set_av_tags(s3_client, s3_object, scan_result, scan_signature, result_time)

    if AV_STATUS_SNS_ARN not in [None, ""]:
        sns_scan_results(
            sns_client,
            s3_object,
            AV_STATUS_SNS_ARN,
            scan_result,
            scan_signature,
            result_time,
        )

    metrics.send(
        env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result
    )
    return scan_result, scan_signature


def scan_one_object(
    s3_object,
    *,
    skip_def_update=False,
    s3_resource=None,
    s3_client=None,
    sns_client=None,
):
    """
    Download the S3 object, scan with ClamAV, set tags/metadata, publish SNS, send metrics.
    Used by both the Lambda handler and the ECS queue worker.

    When skip_def_update=True (ECS worker), def updates are handled by a background thread;
    pass s3_resource, s3_client, sns_client for connection reuse.
    """
    s3 = s3_resource if s3_resource is not None else boto3.resource("s3")
    s3_client = s3_client if s3_client is not None else boto3.client("s3")
    sns_client = sns_client if sns_client is not None else boto3.client("sns")
    ENV = os.getenv("ENV", "")

    start_time = get_timestamp()
    print("Script starting at %s\n" % (start_time), flush=True)

    if str_to_bool(AV_PROCESS_ORIGINAL_VERSION_ONLY):
        verify_s3_object_version(s3, s3_object)

    if AV_SCAN_START_SNS_ARN not in [None, ""]:
        start_scan_time = get_timestamp()
        sns_start_scan(sns_client, s3_object, AV_SCAN_START_SNS_ARN, start_scan_time)

    file_path = get_local_path(s3_object, "/tmp")
    create_dir(os.path.dirname(file_path))
    scan_result = None

    try:
        s3_object.download_file(file_path)

        if not skip_def_update:
            to_download = clamav.update_defs_from_s3(
                s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
            )
            for download in to_download.values():
                s3_path = download["s3_path"]
                local_path = download["local_path"]
                print(
                    "Downloading definition file %s from s3://%s"
                    % (local_path, s3_path),
                    flush=True,
                )
                s3.Bucket(AV_DEFINITION_S3_BUCKET).download_file(s3_path, local_path)
                print(
                    "Downloading definition file %s complete!" % (local_path),
                    flush=True,
                )

        s3_uri = "s3://%s/%s" % (s3_object.bucket_name, s3_object.key)
        print("Starting scan of %s (local path: %s)" % (s3_uri, file_path), flush=True)
        scan_start = time.time()
        scan_result, scan_signature = clamav.scan_file(file_path)
        scan_elapsed = time.time() - scan_start
        print(
            "Scan completed for %s in %.2f s - result: %s\n"
            % (s3_uri, scan_elapsed, scan_result),
            flush=True,
        )

        result_time = get_timestamp()
        if "AV_UPDATE_METADATA" in os.environ:
            set_av_metadata(s3_object, scan_result, scan_signature, result_time)
        set_av_tags(s3_client, s3_object, scan_result, scan_signature, result_time)

        if AV_STATUS_SNS_ARN not in [None, ""]:
            sns_scan_results(
                sns_client,
                s3_object,
                AV_STATUS_SNS_ARN,
                scan_result,
                scan_signature,
                result_time,
            )

        metrics.send(
            env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result
        )
    finally:
        try:
            os.remove(file_path)
        except OSError:
            pass

    should_delete_infected = (
        scan_result is not None
        and str_to_bool(AV_DELETE_INFECTED_FILES)
        and scan_result == AV_STATUS_INFECTED
    )
    if should_delete_infected:
        delete_s3_object(s3_object)
    stop_scan_time = get_timestamp()
    print("Script finished at %s\n" % stop_scan_time, flush=True)


def lambda_handler(event, context):
    EVENT_SOURCE = os.getenv("EVENT_SOURCE", "S3")
    s3_object = event_object(event, event_source=EVENT_SOURCE)
    if AV_EXPECTED_BUCKET_KEY and AV_EXPECTED_BUCKET_KEY not in s3_object.key:
        print("Skipping scan for non ecg file - %s" % (s3_object.key), flush=True)
        return
    scan_one_object(s3_object)


def str_to_bool(s):
    """Convert string to bool; compatible with distutils.util.strtobool (removed in Python 3.12)."""
    v = str(s).lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off"):
        return False
    raise ValueError("Invalid truth value: %s" % s)
