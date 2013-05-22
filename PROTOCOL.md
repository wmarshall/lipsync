The LipSync Protocol
=====================

The Protocol specifies a means for securely transmitting messages to a remote host, and a series of messages that should be sent to sync the tables.

Message Format
---------------

1. Each message's plaintext is a JSON Object, consisting of 16-byte segments called blocks, with an ASCII End Transmission Block (ETB) character (0x17) as the last byte

        {key:"value"} (14 bytes)

2. However, since not all messages are 15, 31... bytes long, we pad each message with the ASCII Space character (0x20) until its length satisfies (length + 1) % 16 == 0

        {key:"value"}\0x20 (15 bytes)

3. Then, we append the ETB character. Our message now ends on a block boundary and can be parsed by most JSON libraries with the ETB trimmed off.

        {key:"value"}\0x20\0x17 (16 bytes)

4. The insistence on blocks of 16 bytes is due to the use of the AES-256 symettric block cipher in CTR mode for message security. The key used is the SHA-256 hash of the secret string provided to the module. The counter function returns 0xdeadbeefdeadbeef000000000000000000 + times called, where deadbeefdeadbeef is replaced by the last 8 bytes of the key.

5. Blocks are encrypted before sending, and are decrypted one at a time on the recieving end, with the reciever checking the last block of each message ETB.

6. Socket timeout is 30 seconds between bytes on each end, after which the side where the timeout is hit sends the Terminate message.

Messages - By Order of Transmission
---------


1. Auth - Client

        {
        LipSync_Version:1.0,
        LipSync_Digest:"SHA256HEXDIGESTOFSECRET"
        }

2. Auth - Server

        {
        LipSync_Version:1.0,
        LipSync_Digest:"SHA256HEXDIGESTOFSECRET"
        }
    If Client's Auth message is unacceptable, respond with Terminate instead

3. Auth Response - Client

        {
        LipSync_Continue:true
        }
    If the server's Auth message is unacceptable, respond with Terminate instead

4. Auth Response - Server

        {
        LipSync_Continue = True
        }

5. Status - Client

        {
        table:"tablenametosync",
        uuids:["uuidinth-etab-lein-stan-dardform",...]
        }

6. Status - Server

        {
        table:"tablenametosync",
        uuids:["uuidinth-etab-lein-stan-dardform",...]
        }
    If server does not have the table requested by the client, respond with Terminate instead

7. Request - Client

        {
        need:["auuidtha-tisi-noth-ersi-desuuids",...]
        }
    If the server's table value did not match the client's table, respond with Terminate instead

8. Request - Server

        {
        need:["auuidtha-tisi-noth-ersi-desuuids",...]
        }

9. Response - Server

    For each uuid in the Client's Request:

        {
        uuid:UUID,
        record:{rowname:"value",...}
        }

10. Response - Client

    For each uuid in the Client's Request:

        {
        uuid:UUID,
        record:{rowname:"value",...}
        }

11. Done - Server

        {
        LipSync_Done:true
        }

12. Done - Client

        {
        LipSync_Done:true
        }

13. Terminate - Server

        {
        LipSync_Continue:false
        }
    Commit the transaction, then hold the socket open for 30 seconds (The default timeout) waiting for the Client's termination message.
    This step is jumped to immediately if an error occurs. If the Client sends a termination message, jump to this step.

14. Terminate - Client

        {
        LipSync_Continue:false
        }
    Commit the transaction, then hold the socket open for 30 seconds (The default timeout) waiting for the Server's termination message.
    This step is jumped to immediately if an error occurs. If the Server sends a termination message, jump to this step.

**Note:** After the Request message, processing of the Response, Done and Terminate steps will occur as fast as possible, without waiting for the other side.
