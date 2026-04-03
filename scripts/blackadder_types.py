from pathlib import Path

from sqlalchemy import ForeignKey, String, Integer, CHAR

from typing import Optional
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

import os

class Base(DeclarativeBase):
    pass


class Binary(Base):
    __tablename__ = "binaries"
    
    id: Mapped[int] = mapped_column(primary_key=True)

    md5sum: Mapped[str] = mapped_column(String(), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String())
    debug_link: Mapped[Optional[str]] = mapped_column(String()) 

    def __repr__(self):
        return f'{self.id} {self.md5sum} {self.name} {self.debug_link}'

    pass

class BinaryLocator(Base):
    __tablename__ = "binary_locators"
    
    id: Mapped[int] = mapped_column(primary_key=True)

    md5sum: Mapped[Optional[str]] = mapped_column(ForeignKey("binaries.md5sum"), nullable=False, )

    name: Mapped[str] = mapped_column(String())
    path: Mapped[str] = mapped_column(String()) 
    mtime: Mapped[int] = mapped_column(Integer())

    def __repr__(self):
        return f'{self.md5sum} {self.name} {self.path} {self.mtime}'
    pass

class SectionHeader(Base):
    __tablename__ = "sections"

    id: Mapped[int] = mapped_column(primary_key=True)

    binary_id: Mapped[int] = mapped_column(ForeignKey("binaries.id"))

    idx: Mapped[int] = mapped_column(Integer())
    name: Mapped[str] = mapped_column(String())
    size: Mapped[int] = mapped_column(Integer())
    vma: Mapped[int] = mapped_column(Integer())
    lma: Mapped[int] = mapped_column(Integer())
    off: Mapped[int] = mapped_column(Integer())
    align: Mapped[int] = mapped_column(Integer())

    def __repr__(self):
        return f"{self.idx:3d} {self.name:48s} {self.size:#10x} {self.vma:#12x} {self.lma:#12x} {self.off:#10x} {self.align:2}"

class Symbol(Base):
    __tablename__ = "symbols"

    id: Mapped[int] = mapped_column(primary_key=True)

    binary_id: Mapped[int] = mapped_column(ForeignKey("binaries.id"))

    address: Mapped[int] = mapped_column(Integer())
    size: Mapped[int] = mapped_column(Integer())
    scope: Mapped[str] = mapped_column(CHAR())
    sym_type: Mapped[str] = mapped_column(CHAR())
    section: Mapped[str] = mapped_column(String())
    name: Mapped[str] = mapped_column(String())

    def __repr__(self):
        return f"{self.address:#12x} {self.size:#8x} {self.sym_type} {self.section} {self.scope} {self.name}"
    pass


class BinaryFinder:
    def __init__(self, config):
        self.config = config
        paths = self.config['paths']['rootfs'].strip().split(':')
        debug_paths = self.config['paths']['debugfs'].strip().split(':')

        self.paths = [Path(x) for x in paths]
        self.debug_paths = [Path(x) for x in debug_paths]

    def findBinary(self, name):
        ret_binlocators = []
        path = Path(name)

        if path.is_absolute():
            path = path.relative_to('/')

        for p in self.paths:
            fp = p / path
            if fp.exists():
                stat = os.stat(fp)
                ret_binlocators.append(BinaryLocator(md5sum=None, name=name, path=str(fp), mtime=int(stat.st_mtime)))

        return ret_binlocators

    def findDebugBinary(self, name, debug_link):
        ret_binlocators = []

        path = Path(name)

        debug_path = Path(debug_link)
        if debug_path.is_absolute():
            debug_path = debug_path.relative_to('/')
        else:
            debug_path = path.parent / debug_path
            if debug_path.is_absolute():
                debug_path = debug_path.relative_to('/')

        for p in self.debug_paths:
            fp = p / debug_path 
            # print(f'checking for path: {fp}')
            if fp.exists():
                stat = os.stat(fp)
                ret_binlocators.append(BinaryLocator(md5sum=None, name=debug_link, path=str(fp), mtime=int(stat.st_mtime)))

        return ret_binlocators



