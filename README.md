sectra
==========

sectra stands for **Sec**rets **Tra**nsport. Sensitive information is encrypted and securely transfered by piggybacking on the SSH v2 protocol.
It's essential a funny behaving SSH server.

#### Usage:

- _sectra_ itself needs a host key pair to work. If no SSH key pair exists in `sectra/host_key`, a new _host key_ pair will be generated automatically by _sectra_ (requires `ssh-keygen` command to be found in `PATH`).
  - **Warning:** The newly created SSH _private_ key will be generated *without* a passphrase. So please keep it private or better yet, _delete it directly after it's not needed anymore._ 

###### Create the user-specific subdirectories:
	
- _The Up&Running way:_  
	If the user who should connect tot the _sectra_ server has one ore more public SSH keys added to his  [GitHub](https://github.com/) profile, then the fastest way to use them with _sectra_ is: 

            $ ./binaries/osx/fetchghkeys <GitHub username>

	This will create a new subdirectory `./data/<GitHub username>`, which contains the `authorized_keys` file containing the fetched public SSH keys for the user given by `<GitHub username>`.  
	Last thing to do is to create a file `./data/<GitHub username>/payload` and put the actual sensitive data to transport into it. Then the the _sectra_ server can be started.

- _The manual way:_  
	Create a subdirectory under the `data` directory which has to match a SSH username that should be allowed to connect to the sectra server. Inside the user-sepcific subdirectory, the public SSH keys of the user who is allowed to connect have to be placed in a file named `authorized_keys` in the same format as used by  [OpenSSH](http://www.openssh.com/).
A file named `payload` in the same user-sepcific subdirectory contains the actually sensitive information which should be transfered (make sure it uses DOS line endings (`:set ff=dos` in Vim)).

	- Example directory structure:
	
	        .
	        ├── data
	        │   └── username
	        │       ├── authorized_keys
	        │       └── payload
	        ├── host_key
	        │   ├── id_rsa
	        │   └── id_rsa.pub

#### How to run the _sectra_ server (OS X):

    	# optional (default port is 3333):
    	#export PORT=3456
    	# run the sectra server:
    	$ ./binaries/osx/sectra

#### How to connect to the _sectra_ server:

        $ ssh -q username@<sectra-HOST-IP> -p 3333
If nothing gets displayed on the console, run the `ssh` command with `-vvv` to see debug messages.

#### License

Licensed under the MIT License. See the LICENSE file for details.

#### TODO

- Tests!
