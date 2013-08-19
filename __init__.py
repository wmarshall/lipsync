# Reference implementation of LipSync
from uuid import uuid4
from select import select
from time import strftime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from threading import Thread
import logging
import json
import socket
import re

from random import randint
from time import sleep


DEFAULT_HANDLER = logging.StreamHandler()

UUID_COL_NAME = '_lipsync_uuid'
LOCAL_ID_COL_NAME = '_local_lipsync_id'
SQLITE_LOCAL_ID_COL_NAME = '_rowid_'
ETB = chr(0x17)
CONTINUE = 'LipSync_Continue'
DONE = 'LipSync_Done'
VERSION = 'LipSync_Version'
DIGEST = 'LipSync_Digest'
__version__ = '1.0'

TIMEOUT = 30

PARAM_PYFORMAT = 'pyformat'
PARAM_QMARK = 'qmark'
PARAM_NUMERIC = 'numeric'
PARAM_NAMED = 'named'
PARAM_FORMAT = 'format'
FORMATS = [PARAM_PYFORMAT, PARAM_QMARK, PARAM_NUMERIC, \
    PARAM_NAMED, PARAM_FORMAT]

_PYFORMAT_RE = re.compile('%\((.+?)\)s')

THREADSAFETY_NONE = 0
THREADSAFETY_MODULE = 1
THREADSAFETY_CONNECTION = 2
THREADSAFETY_CURSOR = 3

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

class ParamError(LipSyncError):
    pass

class SyncThread(Thread):
    def __init__(self, sock, connection, secret, encoder = None,
                 decoder_hook = None, log_handler = None,
                 paramstyle = PARAM_PYFORMAT,
                 threadsafety = THREADSAFETY_CONNECTION, sqlite_hack = False):
        """
        Constructs a thread that syncs with a client connected to sock using \
            the database connection. Should not be directly used in most cases.
        """
        super(SyncThread, self).__init__()
        self.sock = sock
        self.lss = LipSyncServer(connection, secret, encoder, decoder_hook,
            log_handler = log_handler, paramstyle = paramstyle,
            threadsafety = threadsafety, sqlite_hack = sqlite_hack)

    def run(self):
        self.lss.logger.debug('Starting SyncThread')
        self.lss.sync(self.sock)

class LipSyncBase():

    """Base class for LipSync objects. Should not be used directly."""
    def __init__(self, connection, secret, encoder = None, decoder_hook = None,
                 logger = 'LipSync', log_handler = None,
                 paramstyle = PARAM_PYFORMAT,
                 threadsafety = THREADSAFETY_CONNECTION, sqlite_hack = False):
        """
        Base constructor for LipSync objects.

        Parameters:
        connection -- A DB 2.0 (see PEP 249) connection to a relational \
            database.
        secret -- A string representing a secret passphrase known to the \
            server and all clients.
        encoder -- An optional json.JSONEncoder used when serializing objects.
        decoder_hook -- An optional callable that returns a specialized object \
            from a serialized JSON object.
        logger -- An optional string or logging.Logger object that is used to \
            recieve debug information. Defaults to 'LipSync'.
        log_handler -- An optional logging.LogHandler object that is used to \
            route debug information.
        paramstyle -- An optional string that denotes what parameter style the \
            connection object uses. Typically, the database module's \
            paramstyle attribute can be used, but the PARAM_* constants \
            have been provided for convenience.
        threadsafety -- An optional int that denotes how threadsafe the \
            database connection is, used for a multithreaded server. \
            Typically, the database module's threadsafety attribute can be \
            used, but the THREADSAFETY_* constants have been provided for \
            convenience.
        sqlite_hack -- A boolean indicating if the connection is to an SQLite \
            database. Used mostly to work around SQLite's minimalism.
        """

        self.conn = connection
        self.secret = secret
        self.key = SHA256.new(secret)
        self.encoder = encoder
        self.decoder_hook = decoder_hook
        if paramstyle not in FORMATS:
            raise
        self.paramstyle = paramstyle
        self.sqlite_hack = sqlite_hack
        self.threadsafety = threadsafety
        self.reset_crypto()
        try:
            self.logger = logging.getLogger(logger)
        except:
            self.logger = logger
        self.logger.setLevel(logging.DEBUG)
        self.log_handler = log_handler
        if log_handler:
            self.logger.addHandler(log_handler)
        else:
            self.logger.removeHandler(DEFAULT_HANDLER)
            self.logger.addHandler(DEFAULT_HANDLER)
	self.logger.debug(self.key.hexdigest()[-16:])

    def reset_crypto(self):
        self.AESEncrypter = AES.new(self.key.digest(), AES.MODE_CTR,
            counter = Counter.new(64,
                prefix = self.key.digest()[-8:], initial_value = 0))
        self.AESDecrypter = AES.new(self.key.digest(), AES.MODE_CTR,
            counter = Counter.new(64,
                prefix = self.key.digest()[-8:], initial_value = 0))

    def mogrify(self, query, parameters = None):
        if not parameters:
            return query, []
        if self.paramstyle == PARAM_PYFORMAT:
            return query, parameters
        elif self.paramstyle == PARAM_QMARK:
            qparams = _PYFORMAT_RE.findall(query)
            return _PYFORMAT_RE.sub('?', query), \
                [parameters[x] for x in qparams]
        elif self.paramstyle == PARAM_NUMERIC:
            qparams = _PYFORMAT_RE.findall(query)
            count = 0
            def replnumeric(match):
                count += 1
                return ':' + str(count)
            return _PYFORMAT_RE.sub(replnumeric, query), \
                [parameters[x] for x in qparams]
        elif self.paramstyle == PARAM_NAMED:
            qparams = _PYFORMAT_RE.findall(query)
            def replnamed(match):
                return ':' + match.group()
            return _PYFORMAT_RE.sub(replnamed, query), \
                [parameters[x] for x in qparams]
        elif self.paramstyle == PARAM_FORMAT:
            qparams = _PYFORMAT_RE.findall(query)
            return _PYFORMAT_RE.sub('%s', query), \
                [parameters[x] for x in qparams]



    def init_table(self, table):
        cur = self.conn.cursor()
        cols = self.get_col_map(table, omit_local = False)
        if UUID_COL_NAME not in cols:
            cur.execute(*self.mogrify('ALTER TABLE ' + table + ' ADD COLUMN ' +
                        UUID_COL_NAME + ' UUID'))
        if (not self.sqlite_hack) and LOCAL_ID_COL_NAME not in cols:
            cur.execute(*self.mogrify('ALTER TABLE ' + table + ' ADD COLUMN ' +
                        LOCAL_ID_COL_NAME + ' SERIAL UNIQUE'))
        self.conn.commit()

    def update_table(self, table):
        self.init_table(table)
        cur = self.conn.cursor()
        temp_col_name = LOCAL_ID_COL_NAME
        if self.sqlite_hack:
            temp_col_name = SQLITE_LOCAL_ID_COL_NAME
        cur.execute(*self.mogrify('SELECT ' + temp_col_name + ' FROM ' + table +
                    ' WHERE ' + UUID_COL_NAME + ' IS NULL'))
        rows = cur.fetchall();
        for row in rows:
            cur.execute(*self.mogrify('UPDATE ' + table + ' SET ' +
                UUID_COL_NAME + ' = %(u)s WHERE ' + temp_col_name + ' = %(i)s',
                {'u': uuid4().hex, 'i': row[0]}))
        self.conn.commit()

    def get_col_map(self, table, omit_local = True):
        cur = self.conn.cursor()
        cols = []
        cur.execute(*self.mogrify('SELECT * FROM ' + table))
        cols = [ col[0] for col in cur.description ]
        if omit_local:
            if not self.sqlite_hack:
                cols.remove(LOCAL_ID_COL_NAME)
        self.conn.commit()
        return cols

    def get_uuid_map(self, table):
        cur = self.conn.cursor()
        uuids = []
        cur.execute(*self.mogrify('SELECT ' + UUID_COL_NAME + ' FROM ' + table))
        for uuid in cur.fetchall():
            uuids.append(uuid[0])
        self.conn.commit()
        return uuids

    def create_continue_message(self, cont):
        return {CONTINUE: cont}

    def process_auth_message(self, sock):
        if not self.auth_valid(self.get_message(sock)):
            raise AuthError('Invalid secret, aborting')
        self.logger.debug('Auth Successful')

    def process_auth_response(self, sock):
        try:
            self.check_terminated(self.get_message(sock))
        except LipSyncError:
            raise AuthError('Other side rejected Auth')

    def send_auth_message(self, sock):
        self.send_message(sock, self.create_auth_message())

    def send_auth_response(self, sock, status):
        self.send_message(sock, self.create_continue_message(status))

    def auth_valid(self, auth):
        return auth[VERSION] == __version__ and \
                auth[DIGEST] == self.key.hexdigest()

    def create_auth_message(self):
        return {
                VERSION:__version__,
                DIGEST:self.key.hexdigest()
                }

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

    def process_request_message(self, sock):
        message = self.get_message(sock)
        return message['need']

    def send_request_message(self, sock, needed_records):
        self.send_message(sock, {'need': [record for record in needed_records]})

    def do_request(self, sock, needed_records):
        self.send_request_message(sock, needed_records)
        records_to_send = self.process_request_message(sock)
        self.logger.debug('Need to Send ' + str(records_to_send))
        return records_to_send

    def process_response(self, sock, table, needed_records):
        cur = self.conn.cursor()
        while True:
            message = self.check_terminated(self.get_message(sock))
            if message.get(DONE):
                self.logger.debug('Other side done sending')
                break
            elif message['uuid'] not in needed_records:
                continue
            try:
                self.logger.debug('Processing record = '+str(message['record']))
                for key in message['record'].keys():
                    """
                    Fill in missing data to prevent nasty coercion of null \
                        values.
                    This should probably be unnecessary, but it's a useful \
                        trick for buggy clients.
                    """
                    if not message['record'].get(key):
                       message['record'][key] = 0
                message['record'][UUID_COL_NAME] = message['uuid']
                cur.execute(*self.mogrify('INSERT INTO ' + table + '(' +
                            ', '.join(message['record'].keys()) + ') VALUES (' +
                            ', '.join(
                                ['%('+x+')s' for x in message['record'].keys()]
                                ) +')', message['record']))
                self.conn.commit()
            finally:
                self.conn.rollback()
                cur.execute(*self.mogrify('SELECT * FROM '+table))
                self.logger.debug('Table contents' + str(cur.fetchall()))

    def send_response_messages(self, sock, table, uuids):
        cols = self.get_col_map(table)
        cols.remove(UUID_COL_NAME)
        cur = self.conn.cursor()
        for uuid in uuids:
            cur.execute(*self.mogrify('SELECT ' + ', '.join(cols) + ' FROM ' +
                table + ' WHERE ' + UUID_COL_NAME + ' = %(u)s', {'u': uuid}))
            col_data_dict = dict(zip(cols, cur.fetchone()))
            self.send_message(sock, {'uuid': uuid, 'record': col_data_dict})
        self.send_message(sock, {DONE:True})
        self.conn.commit()

    def do_response(self, sock, table, needed_records, need_to_send):
        self.send_response_messages(sock, table, need_to_send)
        self.process_response(sock, table, needed_records)

    def terminate(self, sock):
        self.logger.debug('Terminating at '+ str(strftime('%H:%M:%S')))
        self.send_message(sock, self.create_continue_message(False))
        self.logger.debug('Sent Term Message')
        message = None
        while (not message) or (message.get(CONTINUE)):
            if not select([sock],[],[], TIMEOUT)[0]:
                self.logger.debug('Timeout')
                break
            else:
                self.logger.debug('Getting message')
                message = self.get_message(sock)

    def check_terminated(self, message):
        if message.get(CONTINUE) is False:
            raise TerminatedError('Other side disconnected')
        return message

    def get_block(self, sock):
        buf = ''
        offset = 0
        tries = 0
        while offset < AES.block_size:
            try:
                rx = sock.recv(AES.block_size - offset)
                offset += len(rx)
                buf += rx
            except Exception as e:
                if tries < 5:
                    raise e
        return buf

    def get_message(self, sock):
        ciphertext = ''
        message = ''
        try:
            while True:
                block = self.get_block(sock)
                message += self.AESDecrypter.decrypt(block)
                start_len = len(ciphertext)
                if message[-1] == ETB:
                    break
            message = json.loads(message[:-1], object_hook = self.decoder_hook)
            return message
        finally:
            self.logger.debug('Got message | ' + str(message) + ' |')

    def send_message(self, sock, message):
        plaintext = json.dumps(message, cls = self.encoder)
        while (len(plaintext) + 1) % AES.block_size != 0:
            plaintext += ' '
        plaintext+=ETB
        self.logger.debug('Padded = |'+ plaintext+'|')
        self.logger.debug('msglen = '+str(len(plaintext)))

        ciphertext = self.AESEncrypter.encrypt(plaintext)
        length = len(plaintext)
        while length != 0:
            self.logger.debug('Length to send = '+str(length))
            length -= sock.send(ciphertext[len(ciphertext)-length:])
            self.logger.debug('Sent ' + str(message))

    def sync(self, sock, table = None):

        """
        Syncs with a remote machine.

        Parameters:
        sock -- A socket.socket (or similar) object that is connected to a \
            remote host.
        table -- An optional string representing the name of the table to \
            sync, or None for server mode. Defaults to None
        """

        sock.settimeout(TIMEOUT)
        try:
            self.do_auth(sock)
            table, needed_records = self.do_status(sock, table)
            need_to_send = self.do_request(sock, needed_records)
            self.do_response(sock, table, needed_records, need_to_send)
            self.conn.commit()
        except LipSyncError as e:
            self.logger.debug('Exception ' + str(e))
        finally:
            self.terminate(sock)
            sock.close()
            self.conn.rollback()
            self.reset_crypto()
            self.logger.debug('Socket Closed')

class LipSyncClient(LipSyncBase):

    """
    An object representing a LipSync Client.

    Requires a string representing the table to sync for the sync() method.
    Cannot be interchanged with a LipSyncServer.
    """

    def do_status(self, sock, table):
        self.update_table(table)
        self.send_status_message(sock, table)
        table, needed_records = self.process_status_message(sock, table)
        self.logger.debug('Needed Records = '+str(needed_records))
        return table, needed_records

    def process_status_message(self, sock, table):
        message = self.check_terminated(self.get_message(sock))
        if message['table'] != table:
            raise SyncError('Wanted to sync %s, But server responded with %s'
                            % table, message['table'])
        needed_records = list(set(message['uuids']) -
                              set(self.get_uuid_map(table)))
        return table, needed_records

class LipSyncServer(LipSyncBase):

    """
    An object representing the LipSync Server.

    Does not require a table to sync for the sync() method.
    Cannot be interchanged with a LipSyncClient.
    """

    def listen(self, sock):

        """
        Listens for connections, syncing with valid clients as they connect.

        Parameters:
        sock -- A socket object bound and listening on a port.
        """

        while True:
            try:
                self.logger.debug('Waiting For connection')
                syncsock = sock.accept()[0]
                if self.threadsafety >= THREADSAFETY_CONNECTION:
                    SyncThread(syncsock, self.conn, self.secret, self.encoder,
                        self.decoder_hook, self.log_handler, self.paramstyle,
                        self.threadsafety, self.sqlite_hack).start()
                else:
                    self.sync(syncsock)
            except Exception as e:
                self.logger.debug(e)
                self.conn.rollback()
        sock.close()

    def do_status(self, sock, table):
        table, needed_records = self.process_status_message(sock)
        self.send_status_message(sock, table)
        self.logger.debug('Needed Records = ' +str(needed_records))
        return table, needed_records

    def process_status_message(self, sock):
        message = self.get_message(sock)
        try:
            self.update_table(message['table'])
            needed_records = list(set(message['uuids']) -
                                  set(self.get_uuid_map(message['table'])))
            return message['table'], needed_records
        except Exception as e:
            self.logger.debug(e)
            raise LipSyncError(str(e))
