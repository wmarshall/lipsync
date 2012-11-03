# lipsync.py
# Initial lipsync implementation v0.1
#
# Lipsync is a wrapper around a database that provides syncing capabilites for
# tables.
#
# How it works:
# Wrapper - JSON
# HandShake - Symmetric Encryption of a passphrase, both sides validate
# - Tablename + row order(for hashes) from client
# Status - SHA-1 hashes of each row
# Request - Each side asks for all of the rows they want
# Response - Each side responds with row hash + row data
# Terminate - Lipsync_Exit = True in an otherwise empty object
from hashlib import sha1
from uuid import uuid4
import json

UUID_COL_NAME = '_lipsync_uuid'
LOCAL_ID_COL_NAME = '_local_lipsync_id'

class LSWrapper():
    """WARNING: ONLY SUPPORTS POSTGRESQL/Psycopg2 AS OF 11/3"""
    def __init__(self, connection):
        self.conn = connection

    def init_table(self, table):
        cur = self.conn.cursor()
        cols = self.get_maps(table, omit_local = False)
        try:
            if UUID_COL_NAME not in cols:
                cur.execute('ALTER TABLE %(t)s ADD COLUMN ' + UUID_COL_NAME + ' UUID PRIMARY KEY', {'t': table})
            if LOCAL_ID_COL_NAME not in cols:
                cur.execute('ALTER TABLE %(t)s ADD COLUMN ' + LOCAL_ID_COL_NAME + ' SERIAL PRIMARY KEY', {'t': table})
        except e:
            self.conn.rollback()
            raise e

    def update_table(self, table):
        self.init_table(table)
        cur = self.conn.cursor()
        try:
            cur.execute('SELECT MIN(' + LOCAL_ID_COL_NAME + '), MAX(' + LOCAL_ID_COL_NAME + ') FROM %(t)s WHERE ' + UUID_COL_NAME + ' IS NULL', {'t': table})
            min, max = cur.fetchone();
            for i in range(min, max+1):
                cur.execute('UPDATE %(t)s SET ' + UUID_COL_NAME + ' = %(u)S WHERE ' + LOCAL_ID_COL_NAME + ' = %(i)s', {'t': table, 'u': uuid4(), 'i': i})
            self.conn.commit()
        except e:
            self.conn.rollback()
            raise e

    def get_maps(self, table, omit_local = True):
        cur = self.conn.cursor()
        uuids = []
        hashes = []
        cols = []
        try:
            cur.execute('SELECT ' + UUID_COL_NAME + ' FROM %(t)s', {'t': table})
            for uuid in cur.fetchall():
                uuids.append(uuid[0])
            cur.execute('SELECT * FROM %(t)s', {'t': table})
            for row in cur.fetchall():
                if omit_local:
                    row.remove(LOCAL_ID_COL_NAME)
                hashes.append(sha1(''.join(row).hexdigest())
            cols = [ col.name for col in cur.description ]
            if omit_local:
                cols.remove(LOCAL_ID_COL_NAME)
            self.conn.commit()
        except e:
            self.conn.rollback()
            raise e
        uuid_hash_map = zip(uuids, hashes)
        return (uuid_hash_map, cols)

    def create_handshake_message(self, table):
        return json.dumps({
                    'table' : table,
                    'cols' : self.get_maps(table)[1]
                    })




