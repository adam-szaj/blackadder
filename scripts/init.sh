DBFILE=blackadder.db

rm -f ${DBFILE}
sqlite3 ${DBFILE} < schema.sql

