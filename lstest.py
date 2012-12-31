#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#  lstest.py
#
#  Copyright 2012 Will Marshall <willcodymarshall AT gmail DOT com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
import sys
import socket
import psycopg2
import psycopg2.extras
from lipsync import LipSyncClient, LipSyncServer

addr = ('0.0.0.0',8000)

def main():
    sock = socket.socket()
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        conn = psycopg2.connect(connection_factory=psycopg2.extras.DictConnection,
                            dbname = 'testdb_server')
        sock.bind(addr)
        sock.listen(1)
        print 'Listening on ', addr
        lss = LipSyncServer(conn,'TEST')
        lss.listen(sock)
        sock.close()
        return 0
    conn = psycopg2.connect(connection_factory=psycopg2.extras.DictConnection,
                            dbname = 'testdb_client')
    print 'Connecting to ', addr
    sock.connect(addr)
    print 'Connected'
    lsc = LipSyncClient(conn,'TEST')
    print 'Syncing'
    print lsc.sync(sock, 'test')
    return 0

if __name__ == '__main__':
    main()
