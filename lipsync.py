# lipsync.py
# Initial lipsync implementation v0.1
#
# Lipsync is a wrapper around a database that provides syncing capabilites for
# tables.
#
# How it works:
# Wrapper - JSON
# Lock - Lock the database/ your view of it and enter a transaction
# HandShake -
# - 1. Symmetric Encryption of a passphrase, both sides validate : TODO
# - - 1. "ENCRYPTEDPASS" - no other objects, just string
# - - 2. {LipSync_Auth = False} + Disconnect if Auth not acceptable
# - - 3. Else {LipSync_Auth = True}
# - 2. TableName + row order(for hashes) from client
# Status - UUIDS of each row
# Request - Each side asks for all of the rows they want
# Response - Each side responds with row hash + row data
# Terminate - LipSync_Exit = True in an otherwise empty object
# Commit - Commit the transaction
from hashlib import sha1
from uuid import uuid4
import json

UUID_COL_NAME = '_lipsync_uuid'
LOCAL_ID_COL_NAME = '_local_lipsync_id'

class LipSyncError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)

class AuthError(LipSyncError):
    pass

class LipSyncBase():
    """WARNING: ONLY SUPPORTS POSTGRESQL/Psycopg2 AS OF 11/3"""
    def __init__(self, connection):
        self.conn = connection

    def init_table(self, table):
        cur = self.conn.cursor()
        cols = self.get_cols(table, omit_local = False)
        try:
            if UUID_COL_NAME not in cols:
                cur.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + UUID_COL_NAME + ' UUID')
            if LOCAL_ID_COL_NAME not in cols:
                cur.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + LOCAL_ID_COL_NAME + ' SERIAL PRIMARY KEY')
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def update_table(self, table):
        self.init_table(table)
        cur = self.conn.cursor()
        try:
            cur.execute('SELECT MIN(' + LOCAL_ID_COL_NAME + '), MAX(' +
                        LOCAL_ID_COL_NAME + ') FROM ' + table + ' WHERE ' +
                        UUID_COL_NAME + ' IS NULL')
            min, max = cur.fetchone();
            print min
            print max
            for i in range(min, max + 1):
                cur.execute('UPDATE ' + table + ' SET ' + UUID_COL_NAME +
                ' = %(u)s WHERE ' + LOCAL_ID_COL_NAME + ' = %(i)s',
                {'u': uuid4().hex, 'i': i})
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_col_map(self, table, omit_local = True):
        cur = self.conn.cursor()
        cols = []
        try:
            cur.execute('SELECT * FROM ' + table)
            cols = [ col.name for col in cur.description ]
            if omit_local:
                cols.remove(LOCAL_ID_COL_NAME)
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e
        return cols

    def get_uuid_map(self, table):
        cur = self.conn.cursor()
        uuids = []
        try:
            cur.execute('SELECT ' + UUID_COL_NAME + ' FROM ' + table)
            for uuid in cur.fetchall():
                uuids.append(uuid[0])
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e
        return uuids

    def process_auth(self, fp):
        if not self.auth_valid(json.load(fp)):
            json.dump({'LipSyncAuth': False})
            raise AuthError('Invalid passphrase, aborting')

    def send_auth(self, fp):
        fp.write(self.create_auth_message())

    def auth_valid(self, auth):
        return json.loads(auth) == 'TODO'

    def create_auth_message(self, key):
        return json.dumps('TODO')

class LipSyncClient(LipSyncBase):
    def create_handshake_message(self, table):
        return json.dumps({
                    'table' : table,
                    'cols' : self.get_col_map(table)
                    })


class LipSyncServer(LipSyncBase):
    def create_handshake_message(self, accept=True):
        return json.dumps({
                    'LipSync_Continue': accept
                    })

    def sync(self, fp):
        try:
            self.process_auth(fp)
            self.send_auth(fp)
        finally:
            fp.close()







