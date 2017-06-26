
# Examples
There are two examples that demostrates the use of the Salt channel api:
 * Echo example, the message that is sent to the host is returned to the client.
 * Chatt example, a simple chatt system.

## Build
To build the examples:

    make all

## Run echo example
Start the host:

    $ ./host_prog.out
    Socket created
    bind done
    Waiting for incoming connections...
    
Start the client:

    $ ./client_prog.out
    Connection to 127.0.0.1
    Connected successfully - Please enter string
    Salt handshake succeeded.
    Enter message: 

## Run chatt example
Start the host:

    $ ./host_prog.out
    Socket created
    bind done
    Waiting for incoming connections...    
    
Start the client:

    $ ./client_prog.out
    Connection to 127.0.0.1
    Connected successfully - Please enter string
    Salt handshake succeeded.
    Enter message: 
    
