# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

# The following excerpts are testable examples showing basic library usage.

import uplink
from datetime import datetime, timedelta
from uplink.common.grant import Permission

TEST_ACCESS = "15M6fjomdWMwh4cdbZx5YmDQpQsc8EN73sYKcfLodh6yz6PXEbNJe1WKFvKrwMotebVhRWPiihQoPEuKkaEt1reW5WhPwipmRZnqcfnA483LwehmgUdV1wzftUQ7rArkEJNkVCYJXiaUeWMUNmC2qc6y2nv92LCLQTj2ypoLR7A6ua8yzjEcvfdop5yr12yPMesWvwkqMFwc7gi2GJTnaBrhic55aHfk4K7c1dJuhw33VYHZvsiDU1J2RePppMaxbhTen54cGcNB5Dzz76FjJWSesB4JnHPh7"


def test_restrict_readonly_example():
    """example that restricts an access grant to read-only operations for the next week"""
    now = datetime.now()
    later = now + timedelta(weeks=1)

    permission = Permission(
        allow_delete=False,
        allow_list=True,
        allow_download=True,
        allow_upload=False,
        not_before=now,
        not_after=later,
    )

    access = uplink.parse_access(TEST_ACCESS)
    restricted = access.share(permission)
    print(restricted.serialize())


def test_restrict_uploadonly_example():
    """example that restricts an access grant to uploading short-lived operations for the next week"""

    now = datetime.now()
    later = now + timedelta(weeks=1)

    permission = Permission(
        allow_delete=False,
        allow_list=False,
        allow_download=False,
        allow_upload=True,
        not_before=now,
        not_after=later,
        max_object_ttl=timedelta(hours=1),
    )

    access = uplink.parse_access(TEST_ACCESS)
    restricted = access.share(permission)
    print(restricted.serialize())


def test_register():
    pass
