# -*- coding: utf-8 -*-

import os
import shutil
import tempfile
import unittest

from scan import get_local_path
from worker import _remove_work_dir, _work_dir_for_message


class FakeS3Object(object):
    def __init__(self, bucket_name, key):
        self.bucket_name = bucket_name
        self.key = key


class TestWorkerWorkDir(unittest.TestCase):
    def test_work_dir_for_message(self):
        self.assertEqual(
            _work_dir_for_message("abc-123"),
            "/tmp/av-scan-abc-123",
        )

    def test_remove_work_dir_deletes_owned_root(self):
        work_dir = tempfile.mkdtemp(prefix="av-scan-msg-1-", dir="/tmp")
        try:
            nested = os.path.join(work_dir, "bucket", "uuid", "ecgfile")
            os.makedirs(nested)
            with open(os.path.join(nested, "a.json"), "w") as f:
                f.write("{}")
            _remove_work_dir(work_dir)
            self.assertFalse(os.path.exists(work_dir))
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def test_remove_work_dir_leaves_sibling_intact(self):
        work_a = tempfile.mkdtemp(prefix="av-scan-a-", dir="/tmp")
        work_b = tempfile.mkdtemp(prefix="av-scan-b-", dir="/tmp")
        try:
            for work in (work_a, work_b):
                nested = os.path.join(work, "bucket", "uuid", "ecgfile")
                os.makedirs(nested)
                with open(os.path.join(nested, "file.json"), "w") as f:
                    f.write("{}")

            _remove_work_dir(work_a)
            self.assertFalse(os.path.exists(work_a))
            self.assertTrue(os.path.exists(work_b))
            self.assertTrue(
                os.path.exists(
                    os.path.join(work_b, "bucket", "uuid", "ecgfile", "file.json")
                )
            )
        finally:
            shutil.rmtree(work_a, ignore_errors=True)
            shutil.rmtree(work_b, ignore_errors=True)

    def test_remove_work_dir_refuses_non_av_scan(self):
        other = tempfile.mkdtemp(prefix="other-", dir="/tmp")
        try:
            marker = os.path.join(other, "keep.txt")
            with open(marker, "w") as f:
                f.write("x")
            _remove_work_dir(other)
            self.assertTrue(os.path.exists(other))
            self.assertTrue(os.path.exists(marker))
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_remove_work_dir_noop_on_none(self):
        _remove_work_dir(None)

    def test_same_s3_prefix_different_message_roots(self):
        key = "uuid-111/ecgfile/a.json"
        obj = FakeS3Object("my-bucket", key)
        work_a = _work_dir_for_message("msg-aaa")
        work_b = _work_dir_for_message("msg-bbb")
        path_a = get_local_path(obj, work_a)
        path_b = get_local_path(obj, work_b)
        self.assertNotEqual(path_a, path_b)
        self.assertTrue(path_a.startswith(work_a + os.sep))
        self.assertTrue(path_b.startswith(work_b + os.sep))
        self.assertEqual(os.path.join(work_a, "my-bucket", key), path_a)


if __name__ == "__main__":
    unittest.main()
