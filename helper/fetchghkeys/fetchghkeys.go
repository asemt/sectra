package main

import (
	"fmt"
	"github.com/asemt/sectra/Godeps/_workspace/src/github.com/google/go-github/github"
	"log"
	"os"
	"strings"
)

func main() {

	// Check if exactly one command line arg was provided.
	// Note: First arg is always the path to the running program itself.
	if len(os.Args) != 2 {
		log.Fatalf("(main) >>  Missing GitHub username argument.")
	}

	// Asumption: fetchghkeys gets called standing in the sectra directory:
	//  './sectra/helper/fetchghkeys/fetchghkeys'.
	// Check is we are called from sectra directory.
	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("(main) >>  Error: Could not figure out current working directory: %s", err.Error())
	}
	spltdPth := strings.Split(cwd, string(os.PathSeparator))
	curDirName := spltdPth[len(spltdPth)-1]
	log.Printf("dirName: %s", curDirName)
	if curDirName != "sectra" {
		log.Fatalf("(main) >>  Error, fetchghkeys not called from inside sectra directory.")
	}
	// Check that the current directory has a 'data' subdirectory by trying to step into it.
	err = os.Chdir("data")
	if err != nil {
		log.Fatalf("(main) >>  Error. Could not change into 'data' subdirectory: %s", err.Error())

	}
	// Get the SSH keys from GitHub for the username given by command line argument.
	client := github.NewClient(nil)
	username := os.Args[1]
	keys, _, err := client.Users.ListKeys(username, nil)
	if err != nil {
		log.Printf("(main) >>  Error while ListKeys for user '%s': %s", username, err.Error())
	}
	log.Printf("(main) >>  Found %d public SSH key(s) for user '%s'.\n", len(keys), username)
	// Only going forward if we got at least one GitHub key.
	if len(keys) >= 1 {
		// Check if user-sepcific directory already exists, if so, exit immediateley.
		// equivalent to Python's `if os.path.exists(filename)` --> http://stackoverflow.com/a/12518877
		if _, err := os.Stat(username); err == nil {
			log.Fatalf("(main) >>  Error: Data-subdirectory with username '%s' already exists. Won't override.\n", username)
		}
		// Create a user-specific directory inside 'data' dir.
		err := os.Mkdir(username, 0755)
		if err != nil {
			log.Fatalf("(main) >>  Could not create directory for user '%s': %s", username, err.Error())
		}
		// Create a file 'authorized_keys' for the user.
		akfPth := fmt.Sprintf("./%s/authorized_keys", username)
		f, err := os.Create(akfPth)
		if err != nil {
			log.Fatalf("(main) >>  Could not create file '%s': %s", akfPth, err.Error())
		}
		defer f.Close()
		for _, k := range keys {
			lenK := len(*k.Key)
			wrtn, err := f.WriteString(fmt.Sprintf("%s\n", *k.Key))
			// We've added the newline character.
			if wrtn != (lenK + 1) {
				log.Printf("kLen %d", lenK)
				log.Printf("wrtn %d", wrtn)
				log.Fatalf("(main) >>  Written length != key length.")
			}
			if err != nil {
				log.Fatalf("(main) >>  Error writing SSH key to '%s': %s", akfPth, err.Error())
			}
			log.Printf("(main) >>  Successfully written SSH key with ID %d to '%s'.\n", k.ID, akfPth)
		}
		err = f.Sync()
		if err != nil {
			log.Printf("(main) >>  Error syncing file '%s' after writing: %s", akfPth, err.Error())
		}
	}
        log.Printf("(main) >>  User '%s' has no SSH keys on GitHub. Doing nothing.", username)

} // main
