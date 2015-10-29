sectra
==========

sectra stands for **Sec**rets **Tra**nsport. Sensitive information is encrypted and securely transfered by piggybacking on the SSH v2 protocol.
It's essential a funny behaving SSH server.

#### Usage:

- First make sure you have a SSH keypair - the _host key_ - in place which is used by sectra itself. To create a new _host key_, follow these steps:

        # clone sectra GitHub repo
        $ git clone https://github.com/asemt/sectra
        $ cd sectra/
        # create a new host key pair in the correct directory *without* a passphrase
        $ ssh-keygen -b 4096 -t rsa -f ./host_key/id_rsa -q -N ""

- Secondly create a subdirectory under the `data` directory which has to match a SSH username that should be allowed to connect to the sectra server. Inside the user-sepcific subdirectory, the public SSH key of the user who is allowed to connect has to placed in a file named `id_rsa.pub`.
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
