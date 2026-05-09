# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import datetime
import fnmatch
import logging
import os
import tarfile
from typing import List, Optional

from mvt.common.module import ModuleResults, MVTModule
from mvt.common.utils import convert_datetime_to_iso, convert_unix_to_iso


class SysdiagnoseModule(MVTModule):
    """Base class for all iOS sysdiagnose modules.

    Supports both .tar.gz archives and extracted sysdiagnose directories.
    """

    def __init__(
        self,
        file_path: Optional[str] = None,
        target_path: Optional[str] = None,
        results_path: Optional[str] = None,
        module_options: Optional[dict] = None,
        log: logging.Logger = logging.getLogger(__name__),
        results: ModuleResults = [],
    ) -> None:
        super().__init__(
            file_path=file_path,
            target_path=target_path,
            results_path=results_path,
            module_options=module_options,
            log=log,
            results=results,
        )

        self.tar_archive: Optional[tarfile.TarFile] = None
        self.extract_path: Optional[str] = None
        self.all_files: List[str] = []

    def from_dir(self, extract_path: str, files: List[str]) -> None:
        """Initialize from an extracted sysdiagnose directory."""
        self.extract_path = extract_path
        self.all_files = files

    def from_tar(self, tar_archive: tarfile.TarFile, files: List[str]) -> None:
        """Initialize from an open .tar.gz TarFile handle."""
        self.tar_archive = tar_archive
        self.all_files = files

    def _get_files_by_pattern(self, pattern: str) -> List[str]:
        return fnmatch.filter(self.all_files, pattern)

    def _get_files_by_patterns(self, patterns: List[str]) -> List[str]:
        seen = {}
        for p in patterns:
            for f in self._get_files_by_pattern(p):
                seen[f] = None
        return list(seen)

    def _get_file_content(self, file_path: str) -> bytes:
        if self.tar_archive is not None:
            try:
                member = self.tar_archive.getmember(file_path)
                fh = self.tar_archive.extractfile(member)
                if fh is None:
                    return b""
                data = fh.read()
                fh.close()
                return data
            except KeyError:
                return b""
        else:
            if not self.extract_path:
                return b""
            full_path = os.path.join(self.extract_path, file_path)
            with open(full_path, "rb") as fh:
                return fh.read()

    def _get_file_mtime(self, file_path: str) -> str:
        if self.tar_archive is not None:
            try:
                info = self.tar_archive.getmember(file_path)
                dt = datetime.datetime.fromtimestamp(
                    info.mtime, tz=datetime.timezone.utc
                )
                return convert_datetime_to_iso(dt)
            except KeyError:
                return ""
        else:
            if not self.extract_path:
                return ""
            try:
                mtime = os.stat(
                    os.path.join(self.extract_path, file_path)
                ).st_mtime
                return convert_unix_to_iso(mtime)
            except OSError:
                return ""
