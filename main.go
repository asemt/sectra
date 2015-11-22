/*
 	Inspired by / "borrowed" from:
 	- https://github.com/FiloSottile/whosthere
	- http://blog.scalingo.com/post/104426674353/writing-a-replacement-to-openssh-using-go-12
	- http://blog.scalingo.com/post/105010314493/writing-a-replacement-to-openssh-using-go-22
	- https://vtllf.org/blog/ssh-web-sign-in
	- https://medium.com/@shazow/ssh-how-does-it-even-9e43586e4ffc#.wbi4hsbb1Source
	- https://github.com/Scalingo/go-ssh-examples/blob/master/server_git.go
	- https://godoc.org/golang.org/x/crypto/ssh#example-NewServerConn


	How to connect to this service?
	ssh -q <USERNAME>@<sectra-HOST-IP> -p 3333

*/

package main

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"github.com/asemt/sectra/Godeps/_workspace/src/github.com/juju/deputy"
	"github.com/asemt/sectra/Godeps/_workspace/src/golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
)

var (
	authorizedPubKey ssh.PublicKey
)

// Check if a SSH key pair which is required for sectra to work does exist.
// If not, we are creating one on the fly.
func init() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("(init) >>  Error: Could not figure out current working directory: %s", err.Error())
		os.Exit(1)
	}
	hPriKeyPth := fmt.Sprintf("%s/host_key/id_rsa", cwd)
	_, err = ioutil.ReadFile(hPriKeyPth)
	if err != nil {
		// No private host key found, so we generate one.
		d := deputy.Deputy{
			Errors:    deputy.FromStderr,
			StdoutLog: func(b []byte) { log.Printf("(init) >>  %s", string(b)) },
		}
		log.Println("(init) >>  No private host key found. Generating one...")
		cmd := exec.Command("ssh-keygen", "-b", "4096", "-t", "rsa", "-f", "./host_key/id_rsa", "-q", "-C", "", "-N", "")
		err := d.Run(cmd)
		if err != nil {
			log.Printf("(init) >>  Failed to generate private host key '%s'. Error: %s\n", hPriKeyPth, err.Error())
			os.Exit(1)
		}
		log.Printf("(init) >>  Successfully generated private host key '%s'\n", hPriKeyPth)
	}

}

// Compares to public SSH keys for equality.
func theseTwoPublicKeysAreEqual(one, other ssh.PublicKey) bool {
	oneKeyMshld := ssh.MarshalAuthorizedKey(one)
	otherKeyMshld := ssh.MarshalAuthorizedKey(other)
	if len(oneKeyMshld) != len(otherKeyMshld) {
		return false
	}
	for i, elm := range oneKeyMshld {
		if elm != otherKeyMshld[i] {
			return false
		}
	}
	return true
}

// Reads in the private host key which is used by sectra itself.
func getPrivHostKey() (ssh.Signer, error) {

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("(getPrivHostKey) >>  Error: Could not figure out current working directory: %s", err.Error())
	}

	keyPath := fmt.Sprintf("%s/host_key/id_rsa", cwd)

	hostPrivateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Printf("(getPrivHostKey) >>  Error: Could not read private host key file '%s': %s", keyPath, err.Error())
		return nil, err
	}
	log.Printf("(getPrivHostKey) >>  Successfully retrieved private host key from file '%s'.\n", keyPath)

	hostPrivateKeySigner, err := ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		log.Printf("(getPrivHostKey) >>  Error: Could not create signer from private host key: %s", err.Error())
		return nil, err
	}
	log.Println("(getPrivHostKey) >>  Successfully created signer form private host key.")
	return hostPrivateKeySigner, err
}

// Helper function to read a file line by line.
func readLines(path string) ([][]byte, error) {
	// Contains the contents of the file specified by 'path'.
	var fCnt [][]byte
	inFile, err := os.Open(path)
	if err != nil {
		log.Printf("(readLine) >>  Error opening file '%s': %s", path, err.Error())
		return nil, fmt.Errorf(err.Error())
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)

	for scanner.Scan() {
		fCnt = append(fCnt, scanner.Bytes())
	}
	return fCnt, err
}

// Reads a public SSH key from the file system for a user specified by 'username'.
func getPubKeysForUser(username string) ([]ssh.PublicKey, error) {

	// Contains all authorized public SSH keys for the user specified by 'username'.
	var userAuthKeys []ssh.PublicKey

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("(getPubKeysForUser) >>  Error: Could not figure out current working directory: %s", err.Error())
		return nil, err
	}

	pubKeyPath := fmt.Sprintf("%s/data/%s/authorized_keys", cwd, username)

	authKeyFile, err := os.Open(pubKeyPath)
	if err != nil {
		log.Printf("(getPubKeysForUser) >>  Error opening pub key file '%s' for user '%s': %s", pubKeyPath, username, err.Error())
		return nil, fmt.Errorf("(getPubKeysForUser) >>  Error opening pub key file '%s'", pubKeyPath)
	}
	defer authKeyFile.Close()

	authKeyFileCnt, err := readLines(pubKeyPath)
	if err != nil {
		log.Printf("(getPubKeysForUser) >>  Error reading contents of pub key file '%s' for user '%s': %s", pubKeyPath, username, err.Error())
		return nil, err
	}

	for i, authKey := range authKeyFileCnt {
		authorizedPubKey, _, _, _, err = ssh.ParseAuthorizedKey(authKey)
		if err != nil {
			log.Printf("(getPubKeysForUser) >>  Error: Unable to parse AuthorizedPubKey %d in '%s'. Error: %s", i, pubKeyPath, err.Error())
			return nil, err
		}

		log.Printf("(getPubKeysForUser) >>  Successfully parsed authorized PubKey: %d for user '%s'\n", i, username)
		userAuthKeys = append(userAuthKeys, authorizedPubKey)

	}

	//	var authorizedPubKeyBuf []byte
	//	authorizedPubKeyBuf, err = ioutil.ReadAll(authKeyFile)
	//	if err != nil {
	//		log.Printf("(getPubKeysForUser) >>  Error: Could not read PubKey at path: %s", pubKeyPath)
	//		return nil, err
	//	}
	return userAuthKeys, nil
}

// Generates a MD5 based fingerprint of a SSH key.
func pubKeyFingerprint(key ssh.PublicKey) (string, error) {
	h := md5.New()
	_, err := h.Write(key.Marshal())
	if err != nil {
		return "", err
	}
	fp := fmt.Sprintf("%x", h.Sum(nil))
	return fp, nil
}

// Callback function responsible for authenticating the SSH client.
func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Printf("(keyAuth) >>  New client conn from '%s' authenticating with '%s'\n", conn.RemoteAddr(), key.Type())

	// Create a fingerprint of the external provided pub key.
	fpProvidedPubKey, err := pubKeyFingerprint(key)
	if err != nil {
		log.Printf("(keyAuth) >>  Error: Unable to create fingerprint for provided PubKey: %s\n", err.Error())
	}
	log.Printf("(keyAuth) >>  Fingerprint of provided PubKey    : %s\n", fpProvidedPubKey)

	// Get all the pub keys for a given user.
	authorizedPubKeys, err := getPubKeysForUser(conn.User())
	if err != nil {
		return nil, fmt.Errorf("(keyAuth) >>  No pub key for user '%s' found / user not allowed to connect.", conn.User())

	}

	// Check if the user is allowed to connect at all (meaning: the must be a subdirectory in the 'data' dir
	// matching the provided SSH username).
	var authSuccess bool = false
	for i, authPubKey := range authorizedPubKeys {

		fpAuthorizedPubKey, err := pubKeyFingerprint(authPubKey)
		if err != nil {
			log.Printf("(keyAuth) >>  Error: Unable to create fingerprint for authorized PubKey %d: %s\n", i, err.Error())
		}
		log.Printf("(keyAuth) >>  Fingerprint of authorized PubKey %d: %s\n", i, fpAuthorizedPubKey)

		// Check if username and Public Key combination is allowed to establish a connection.
		if theseTwoPublicKeysAreEqual(key, authPubKey) {
			authSuccess = true
			break

		}
	}
	if authSuccess {
		log.Printf("(keyAuth) >>  Correct username '%s' and public key provided.", conn.User())
		// Signaling success / authentication passed.
		return nil, nil
	}
	log.Printf("(keyAuth) >>  Wrong username '%s' and/or public key provided.", conn.User())
	return nil, fmt.Errorf("Wrong username and/or public key.")
}

// Handle new connection attempts from SSH clients.
func handleNewClientConn(newClientInfoChan chan NewClientInfo) {

	for newClientInfo := range newClientInfoChan {

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		// Switching from a standard TCP connection to an encrypted SSH connection.
		sshServerConn, chans, reqs, err := ssh.NewServerConn(newClientInfo.nConn, &(newClientInfo.serverConfigPtr))
		if err != nil {
			log.Printf("(handleNewClientConn) >>  Error in ssh.NewServerConn: '%s'", err.Error())
			// Go on serving the other SSH client requests.
			continue
		}
		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of a shell, the type is
			// "session" and ServerShell may be used to present a simple
			// terminal interface.
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				panic("could not accept channel.")
			}

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "shell" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					ok := false
					switch req.Type {
					case "shell":
						ok = true
						if len(req.Payload) > 0 {
							// We don't accept any
							// commands, only the
							// default shell.
							ok = false
						}
					}
					req.Reply(ok, nil)
				}
			}(requests)

			go func(sshServerConn *ssh.ServerConn) {
				defer channel.Close()

				cwd, err := os.Getwd()
				if err != nil {
					log.Printf("(handleNewClientConn) >>  Error: Could not figure out current working directory: %s", err.Error())
				}

				payloadPath := fmt.Sprintf("%s/data/%s/payload", cwd, sshServerConn.User())

				payload, err := ioutil.ReadFile(payloadPath)
				if err != nil {
					log.Printf("(handleNewClientConn) >>  Error: Could not read payload file '%s' for user '%s': %s", payloadPath, sshServerConn.User(), err.Error())
					return
				}
				log.Printf("(handleNewClientConn) >>  Successfully retrieved contents of payload file '%s' for user '%s'.\n", payloadPath, sshServerConn.User())
				_, err = channel.Write(payload)
				if err != nil {
					log.Printf("(handleNewClientConn) >>  Error sending payload to SSH client: %s\n", err.Error())
				}
				log.Println("(handleNewClientConn) >>  Successfully sent payload to SSH client.")
			}(sshServerConn)
		}
	}
}

// Information about a connecting SSH client.
type NewClientInfo struct {
	nConn           net.Conn
	serverConfigPtr ssh.ServerConfig
}

func main() {

	clientInfoChan := make(chan NewClientInfo)
	// Keep the server part running and handle the new connection from a SSH client in an own function.
	go handleNewClientConn(clientInfoChan)

	config := &ssh.ServerConfig{
		PublicKeyCallback: keyAuth,
	}
	// Getting the private host key.
	privHostKeySigner, err := getPrivHostKey()
	if err != nil {
		log.Fatalf("(main) >>  Error retrieving the private host key file: %s", err.Error())
	}

	config.AddHostKey(privHostKeySigner)

	port := "3333"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}
	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("(main) >>  Unable to listen at port: %d.\n", port)
		panic(err)
	}
	log.Printf("(main) >>  sectra started. Listening on 0.0.0.0:%s\n", port)

	for {

		nConn, err := socket.Accept()
		if err != nil {
			log.Println("(main) >>  Unable to accept new socket connection.")
			panic(err)
		}

		// Handle the new client connection attempt concurrently.
		clientInfoChan <- NewClientInfo{nConn, *config}
	}

} // main
