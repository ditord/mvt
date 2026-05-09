# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging
import os
import tarfile
from pathlib import Path
from typing import List, Optional

from mvt.common.command import Command
from mvt.common.indicators import Indicators

from .modules.sysdiagnose import SYSDIAGNOSE_MODULES
from .modules.sysdiagnose.base import SysdiagnoseModule

log = logging.getLogger(__name__)


class CmdIOSCheckSysdiagnose(Command):
    """Run sysdiagnose analysis modules against a .tar.gz archive or directory."""

    def __init__(
        self,
        target_path: Optional[str] = None,
        results_path: Optional[str] = None,
        ioc_files: Optional[list] = None,
        iocs: Optional[Indicators] = None,
        module_name: Optional[str] = None,
        serial: Optional[str] = None,
        module_options: Optional[dict] = None,
        hashes: bool = False,
        sub_command: bool = False,
        disable_version_check: bool = False,
        disable_indicator_check: bool = False,
    ) -> None:
        super().__init__(
            target_path=target_path,
            results_path=results_path,
            ioc_files=ioc_files,
            iocs=iocs,
            module_name=module_name,
            serial=serial,
            module_options=module_options,
            hashes=hashes,
            sub_command=sub_command,
            log=log,
            disable_version_check=disable_version_check,
            disable_indicator_check=disable_indicator_check,
        )

        self.name = "check-sysdiagnose"
        self.modules = SYSDIAGNOSE_MODULES

        self.__format: str = ""
        self.__tar: Optional[tarfile.TarFile] = None
        self.__files: List[str] = []

    def from_dir(self, dir_path: str) -> None:
        """Collect all relative file paths from an extracted sysdiagnose directory."""
        self.__format = "dir"
        self.target_path = dir_path
        parent = Path(dir_path).absolute().as_posix()
        for root, _dirs, files in os.walk(os.path.abspath(dir_path)):
            for file_name in files:
                rel = os.path.relpath(
                    os.path.join(root, file_name), parent
                )
                # Normalise to forward slashes for fnmatch on all platforms
                self.__files.append(rel.replace(os.sep, "/"))

    def from_tar(self, archive_path: str) -> None:
        """Open a sysdiagnose .tar.gz and index its members."""
        self.__format = "tar"
        self.__tar = tarfile.open(archive_path, "r:gz")
        for member in self.__tar.getmembers():
            if member.isfile():
                self.__files.append(member.name)

    def init(self) -> None:
        if not self.target_path:
            return

        if os.path.isdir(self.target_path):
            self.from_dir(self.target_path)
        elif os.path.isfile(self.target_path):
            if not tarfile.is_tarfile(self.target_path):
                log.error(
                    "Target %s is not a valid .tar.gz sysdiagnose archive",
                    self.target_path,
                )
                return
            self.from_tar(self.target_path)
        else:
            log.error("Target path does not exist: %s", self.target_path)

    def module_init(self, module: SysdiagnoseModule) -> None:  # type: ignore[override]
        if self.__format == "tar":
            module.from_tar(self.__tar, list(self.__files))
        else:
            module.from_dir(self.target_path or "", list(self.__files))

    def finish(self) -> None:
        if self.__tar:
            self.__tar.close()
