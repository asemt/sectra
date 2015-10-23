sectra
==========

sectra stands for **Sec**rets **Tra**nsport. Sensitive information is encrypted and securely transfered by piggybacking on the SSH v2 protocol.
It's essential a funny behaving SSH server.

#### Usage:

- First make sure you have a SSH keypair in place which is used by sectra itself (generate one with: `ssh-keygen -t rsa -b 4096`). The keypair has to be placed inside the `host_key` directory. The private key file has to be named `id_rsa` and the public key part `id_rsa.pub`. Please be careful with the usage of passphrases in your SSH key. If the SSH key you generate has a passphrase, then you need to make sure that it is added to your SSH agent before you start the service.

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
    	export PORT=3456
    	./sectra

#### How to connect to the _sectra_ server:

        $ ssh -q username@<sectra-HOST-IP> -p 3333

#### License

Licensed under the MIT License. See the LICENSE file for details.

#### TODO

- Tests!
