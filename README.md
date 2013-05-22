LipSync
===============

LipSync is a library that synchronizes relational databases over a bidirectional socket object.
It requires a connection to a relational database and a socket object passed in from the developer.
LipSync is designed to be as simple as possible, abstracting the developer from all of the heavy lifting of syncing.

### What LipSync Will Do

* Sync two idendical tables (each column on the client is matched by a column on the server and vice versa)
* Store persisten metadata in the table, identifying each row with a UUID, typically in the column __lipsync_uuid
* Close your socket after using

### What LipSync Will Not Do

* Synchronize changes in the schema
* Synchronize constraints or resolve integrity errors related to imbalanced constraints on the client or server side
* Leave your data in an inconsistent state


The Name
---------------

LipSync could have been called libsync, but just like a lipsynching performer, it comes with caveats.

* LipSync adds up to two columns to your database.
* LipSync does not support UPDATEs. Changes to a row already synced will be propagated in an undefined way.
* LipSync does not support DELETEs. Deleting a row already synced will likely result in it returning as soon as the database is synced again.
* LipSync does not support partial syncs.
* LipSync will behave in an undefined way if its metadata is tampered with.

Using LipSync
---------------

Using the reference implementation of LipSync is simple.

## Client:

1. Create a socket object and connect it to its destination.
2. Create a database connection object and connect it to a database.
3. Create a LipSyncClient object, passing it the database connection and all relevant arguments.
4. Call the LipSyncClient's sync() method, with the socket as an argument.
5. If no exceptions were raised, your sync was a success.

## Server:

1. Create a socket object and have it listen on any port.
2. Create a database connection and connect it to  a database.
3. Create a LipSyncServer object, passing it the database connection and all relevant arguments.
4. Call the LipSyncServer's listen() method, with the socket as an argument.
5. Ensure that you have some way to kill the LipSyncServer, as it will continue to run until interrupted.

Compatibility
--------------

This implementation of LipSync should work with all DB 2.0 compliant python modules.
However, actual testing has only been done on a few:

* PostgeSQL - Tested extensively
* SQLite - Should work, but not extensively tested
* MySQL - Untested
* Other Databases - Untested
