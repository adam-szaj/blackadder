from blackadder_types import Base, BinaryLocator, Binary


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker()


class DataBase:
    def __init__(self, dbpath: str, echo: bool):
        self.dbpath = dbpath
        self.engine = create_engine(self.dbpath, echo=echo)
        Base.metadata.create_all(bind=self.engine)
        self.session = Session(bind=self.engine)
        pass

    def fetchBinaryByName(self, name: str) -> Binary:
        results = self.session.query(Binary).filter(Binary.name == name)
        for r in results:
            return r
        return None

    def fetchBinaryByMd5Sum(self, md5sum: str) -> Binary:
        results = self.session.query(Binary).filter(Binary.md5sum == md5sum)
        for r in results:
            return r
        return None

    def insertOrUpdateBinary(self, bin: Binary):
        # print(f'insert bin: {bin}')
        self.session.add(bin)
        self.session.commit()
        pass

    def insertOrUpdateBinaryLocator(self, binloc: BinaryLocator):
        self.session.add(binloc)
        self.session.commit()
        pass

    def fetchBinaryLocatorByPath(self, path: str) -> BinaryLocator:
        results = self.session.query(BinaryLocator).filter(
            BinaryLocator.path == str(path)
        )
        for r in results:
            return r
        return None

    pass
