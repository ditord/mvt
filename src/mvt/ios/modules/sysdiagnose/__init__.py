# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

from .crash_reports import CrashReports
from .unified_log import UnifiedLog

SYSDIAGNOSE_MODULES = [
    CrashReports,
    UnifiedLog,
]
