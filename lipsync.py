# lipsync.py
# Initial lipsync implementation v0.1
#
# Lipsync is a wrapper around a database that provides syncing capabilites for
# tables.
#
# How it works:
# Wrapper - JSON - UTF8
# Lock - Lock the database/ your view of it and enter a transaction
# Auth - Symmetric Encryption of a passphrase, both sides validate : TODO
# - 1. "ENCRYPTEDPASS" - no other objects, just string
# - 2. Terminate if Auth not acceptable
# - 3. Else {LipSync_Continue = True}
# Status - set up table to sync
# - 1. {table: tablename, uuids:[UUIDS]} from Client
# - 2. {table: tablename, uuids:[UUIDS]} from server if it can sync tablename
# - - 1. Else Terminate
# Request - Each side asks for all of the rows they want
# - 1. {need: [UUIDS]} from both
# Response - Each side responds with row hash + row data
# - 1. {uuid:UUID, record ={record}}
# - 2. Terminate when done
# Terminate - {LipSync_Continue = False} + wait 30s for {LipSync_Continue = False}
# Commit - Commit the transaction
from hashlib import sha1
from uuid import uuid4
from select import select
from time import strftime
import json
import socket

UUID_COL_NAME = '_lipsync_uuid'
LOCAL_ID_COL_NAME = '_local_lipsync_id'
ETB = chr(0x17)
CONTINUE = 'LipSync_Continue'

TIMEOUT = 30

class LipSyncError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)

class AuthError(LipSyncError):
    pass

class SyncError(LipSyncError):
    pass

class TerminatedError(SyncError):
    pass

class HUPError(SyncError):
    pass

class LipSyncBase():
    """WARNING: ONLY SUPPORTS POSTGRESQL/Psycopg2 AS OF 11/3"""
    def __init__(self, connection):
        self.conn = connection

    def init_table(self, table):
        cur = self.conn.cursor()
        cols = self.get_col_map(table, omit_local = False)
        if UUID_COL_NAME not in cols:
            cur.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + UUID_COL_NAME + ' UUID')
        if LOCAL_ID_COL_NAME not in cols:
            cur.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + LOCAL_ID_COL_NAME + ' SERIAL PRIMARY KEY')
        self.conn.commit()

    def update_table(self, table):
        self.init_table(table)
        cur = self.conn.cursor()
        cur.execute('SELECT ' + LOCAL_ID_COL_NAME + ' FROM ' + table +
                    ' WHERE ' + UUID_COL_NAME + ' IS NULL')
        rows = cur.fetchall();
        for row in rows:
            cur.execute('UPDATE ' + table + ' SET ' + UUID_COL_NAME +
            ' = %(u)s WHERE ' + LOCAL_ID_COL_NAME + ' = %(i)s',
            {'u': uuid4().hex, 'i': row[0]})
        self.conn.commit()

    def get_col_map(self, table, omit_local = True):
        cur = self.conn.cursor()
        cols = []
        cur.execute('SELECT * FROM ' + table)
        cols = [ col.name for col in cur.description ]
        if omit_local:
            cols.remove(LOCAL_ID_COL_NAME)
        self.conn.commit()
        return cols

    def get_uuid_map(self, table):
        cur = self.conn.cursor()
        uuids = []
        cur.execute('SELECT ' + UUID_COL_NAME + ' FROM ' + table)
        for uuid in cur.fetchall():
            uuids.append(uuid[0])
        self.conn.commit()
        return uuids

    def create_continue_message(self, cont):
        return {CONTINUE: cont}

    def process_auth_message(self, sock):
        if not self.auth_valid(self.get_message(sock)):
            raise AuthError('Invalid passphrase, aborting')
        print 'Auth Successful'

    def process_auth_response(self, sock):
        try:
            self.check_terminated(self.get_message(sock))
        except LipSyncError:
            raise AuthError('Other side rejected Auth')

    def send_auth_message(self, sock):
        self.send_message(sock, self.create_auth_message('TODO'))

    def send_auth_response(self, sock, status):
        self.send_message(sock, self.create_continue_message(status))

    def auth_valid(self, auth):
        return auth == 'TODO'

    def create_auth_message(self, key):
        return 'TODO'

    def do_auth(self, sock):
        self.send_auth_message(sock)
        self.process_auth_message(sock)
        self.send_auth_response(sock, True)
        self.process_auth_response(sock)

    def create_status_message(self, table):
        return {
                'table' : table,
                'uuids' : self.get_uuid_map(table)
                }

    def send_status_message(self, sock, table):
        self.send_message(sock, self.create_status_message(table))

    def do_status(self, sock, table):
        if not table:
            self.process_status_message(sock)
            self.send_status_message(sock, table)
        else:
            self.send_status_message(sock, table)
            self.process_status_message(sock)

    def process_request_message(self, sock):
        message = self.get_message(sock)
        return message['need']

    def send_request_message(self, sock, needed_records):
        self.send_message(sock, {'need': [record for record in needed_records]})

    def do_request(self, sock, needed_records):
        self.send_request_message(sock, needed_records)
        records_to_send = self.process_request_message(sock)
        print 'Need to Send ', records_to_send
        return records_to_send

    def process_response(self, sock, table, needed_records):
        cur = self.conn.cursor()
        while True:
            message = self.check_terminated(self.get_message(sock))
            if message['uuid'] not in needed_records:
                continue
            cur.execute('INSERT INTO ' + table + '(' +
                        ', '.join(message['record'].keys()) + ') VALUES (' +
                        ', '.join(['%('+x+')s' for x in message['record'].keys()]) +')', message['record'])
            cur.execute('SELECT * FROM '+table)
            print 'Table contents', cur.fetchall()

    def send_response_messages(self, sock, table, uuids):
        cols = self.get_col_map(table)
        cur = self.conn.cursor()
        for uuid in uuids:
            cur.execute('SELECT ' + ', '.join(cols) + ' FROM ' + table +' WHERE '+
                        UUID_COL_NAME + ' = %(u)s', {'u': uuid})
            col_data_dict = dict(zip(cols, cur.fetchone()))
            self.send_message(sock, {'uuid': uuid, 'record': col_data_dict})
        self.send_message(sock, self.create_continue_message(False))
        self.conn.commit()

    def do_response(self, sock, table, needed_records, need_to_send):
        self.send_response_messages(sock, table, need_to_send)
        self.process_response(sock, table, needed_records)

    def terminate(self, sock):
        print 'Terminating at ', strftime('%H:%M:%S')
        self.send_message(sock, self.create_continue_message(False))
        print 'Sent Term Message'
        message = None
        while (not message) or (message.get(CONTINUE)):
            if not select([sock],[],[], TIMEOUT)[0]:
                print 'Timeout'
                break
            else:
                print 'Getting message'
                message = self.get_message(sock)

    def check_terminated(self, message):
        if message.get(CONTINUE) is False:
            raise TerminatedError('Other side disconnected')
        return message

    def get_message(self, sock):
        message = ''
        try:
            while (not message) or (message[-1] != ETB):
                start_len = len(message)
                message += sock.recv(1)
                if len(message) == start_len:
                    raise HUPError('recv returned no data (HUP?)')
            message = json.loads(message[:-1])
            return message
        finally:
            print 'Got message |', message, '|'

    def send_message(self, sock, message):
        sock.send(json.dumps(message))
        sock.send(ETB)
        print 'Sent ', message

    def sync(self, sock, table = None):
        """ table is None for server mode"""
        #~ sock.setblocking(0)
        sock.settimeout(TIMEOUT)
        try:
            self.do_auth(sock)
            table, needed_records = self.do_status(sock, table)
            need_to_send = self.do_request(sock, needed_records)
            self.do_response(sock, table, needed_records, need_to_send)
        except LipSyncError as e:
            print e.message
        finally:
            self.conn.commit()
            self.terminate(sock)
            #~ sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            print 'Socket Closed'

class LipSyncClient(LipSyncBase):
    def do_status(self, sock, table):
        self.update_table(table)
        self.send_status_message(sock, table)
        table, needed_records = self.process_status_message(sock, table)
        print needed_records
        return table, needed_records

    def process_status_message(self, sock, table):
        message = self.check_terminated(self.get_message(sock))
        if message['table'] != table:
            raise SyncError('Wanted to sync %s. but server responded with %s' % table, message['table'])
        needed_records = list(set(message['uuids']) - set(self.get_uuid_map(table)))
        return table, needed_records

class LipSyncServer(LipSyncBase):

    def listen(self, sock):
        try:
            while True:
                print 'Waiting For connection'
                conn = sock.accept()[0]
                self.sync(conn)
        except:
            sock.close()

    def do_status(self, sock, table):
        table, needed_records = self.process_status_message(sock)
        self.send_status_message(sock, table)
        print needed_records
        return table, needed_records

    def process_status_message(self, sock):
        message = self.get_message(sock)
        try:
            self.update_table(message['table'])
            needed_records = list(set(message['uuids']) - set(self.get_uuid_map(message['table'])))
            return message['table'], needed_records
        except Exception as e:
            print e
            raise LipSyncError(str(e))

