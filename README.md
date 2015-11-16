sectra
==========

sectra stands for **Sec**rets **Tra**nsport. Sensitive information is encrypted and securely transfered by piggybacking on the SSH v2 protocol.
It's essential a funny behaving SSH server.

#### Usage:

- _sectra_ itself needs a host key pair to work. If no SSH key pair exists in `sectra/host_key`, a new _host key_ pair will be generated automatically by _sectra_ (requires `ssh-keygen` command to be found in `PATH`).
  - **Warning:** The newly created SSH _private_ key will be generated *without* a passphrase. So please keep it private or better yet, delete it directly after it's not needed anymore. 

- Create a subdirectory under the `data` directory which has to match a SSH username that should be allowed to connect to the sectra server. Inside the user-sepcific subdirectory, the public SSH key of the user who is allowed to connect has to placed in a file named `id_rsa.pub`.
A file named `payload` in the same user-sepcific subdirectory contains the actually sensitive information which should be transfered (make sure it uses DOS line endings (`:set ff=dos` in Vim)).

- Example directory structure:

        .
        ├── data
        │   └── username
        │       ├── id_rsa.pub
        │       └── payload
        ├── host_key
        │   ├── id_rsa
        │   └── id_rsa.pub

#### How to run the _sectra_ server:

    	# optional (default port is 3333):
    	#export PORT=3456
    	# run the sectra server:
    	$ ./binaries/osx/sectra

#### How to connect to the _sectra_ server (OS X):

        $ ssh -q username@<sectra-HOST-IP> -p 3333
If nothing gets displayed on the console, run the `ssh` command with `-vvv` to see debug messages.

#### License

Licensed under the MIT License. See the LICENSE file for details.

#### TODO

- Tests!
