from dataclasses import dataclass


def prettyPrintDict(d):
    print()
    for k, v in d.items():
        if type(v) is float:
            print(f"{k}: {v}")
        else:
            # print(f"{k}: {v}")
            print(f"{k}: {v.name} {v.type}")
        print()


def mymeta(typ):
    # print(typ.__dict__)
    # print(typ.__annotations__)
    prettyPrintDict(typ.__dataclass_fields__)
    return typ


def sql_pk(typ):
    print(f"type {typ}")
    return typ


@mymeta
@dataclass
class BinaryLocator:
    md5sum: str
    name: str
    # path: Path
    mtime: int
    pass


def main():
    bl = BinaryLocator("123456", "aname", 0)
    print(bl)


if __name__ == "__main__":
    main()
