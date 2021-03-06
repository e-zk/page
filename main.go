package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"

	"github.com/e-zk/page/store"
	"github.com/e-zk/page/term"
	"github.com/e-zk/subc"
	"github.com/e-zk/wslcheck"

	"github.com/atotto/clipboard"
)

const (
	tmpName     = "page-*"
	wslClipPath = "/mnt/c/Windows/system32/clip.exe"
	usageString = `usage: page [command] [args ...]

where [command] can be:
  help  show this help message
  init  generate age keypair
  ls    list password entries
  open  open/view a password entry
  save  save/add a new password entry
  rm    remove password entry

for help with subcommands type: page [command] -h
`
)

var (
	recipientsPath string
	privateKeyPath string
	storePath      string
)

// wrapper for Fprintf to print to stderr
func errPrint(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
}

// main usage/help message
func usage() {
	errPrint(usageString)
}

// clipboard function
func clip(text string) (err error) {
	wsl, err := wslcheck.Check()
	if err != nil {
		return err
	}

	if wsl {
		cmd := exec.Command(wslClipPath)
		cmd.Stdin = bytes.NewBuffer([]byte(text))
		err = cmd.Run()
		if err != nil {
			return err
		}
	} else {
		err = clipboard.WriteAll(text)
		if err != nil {
			return err
		}
	}

	return nil
}

// get XDG_DATA_HOME
func userDataDir() (string, error) {
	var path string
	path = os.Getenv("XDG_DATA_HOME")
	if path == "" {
		path = os.Getenv("HOME")
		if path == "" {
			return "", errors.New("neither $XDG_DATA_HOME nor $HOME are defined")
		}
		path += "/.local/share"
	}
	return path, nil
}

// Read the recipient file and return an age.X25519Recipient
func getRecipients() (*age.X25519Recipient, error) {
	var pubkey []byte
	if _, err := os.Stat(recipientsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("recipients file does not exist.\ndid you forget to run `page init'?")
	}

	pubkey, err := os.ReadFile(recipientsPath)
	if err != nil {
		return nil, nil
	}
	return age.ParseX25519Recipient(string(pubkey))
}

// Read the private key and return an age.X25519Identity
func getIdentity() (*age.X25519Identity, error) {
	var privkey []byte
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("private key file does not exist.\ndid you forget to run `page init'?")
	}

	privkey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil
	}

	var strippedPrivkey string

	for _, line := range strings.Split(string(privkey), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		strippedPrivkey = line
	}

	return age.ParseX25519Identity(strippedPrivkey)
}

// generate age key pair
func initKeys() {
	pk, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatal(err)
	}

	pkFd, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		log.Fatal(err)
	}
	rFd, err := os.OpenFile(recipientsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := pkFd.Close(); err != nil {
			log.Fatal(err)
		}
		if err := rFd.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	fmt.Fprintf(pkFd, "%s", pk)
	fmt.Fprintf(rFd, "%s", pk.Recipient())
}

// List all password entries
func list() {
	s := store.Store{Path: storePath}

	entries, err := s.Entries()
	if err != nil {
		log.Fatal(err)
	}

	for _, e := range entries {
		fmt.Printf("%s\n", e)
	}
}

// Remove a password entry
func remove(force bool) {
	entry := subc.Sub("rm").Arg(0)

	// create a new store
	// (we do not require identity/recipient for this operation)
	s := store.Store{Path: storePath}

	// check if the entry exists
	ok, err := s.EntryExists(entry)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		log.Fatalf("entry %s does not exist", entry)
	}

	if !force {
		ch, err := term.Ask("remove entry " + entry + "?")
		if err != nil {
			log.Fatal(err)
		}

		if !ch {
			log.Println("aborted.")
			return
		}
	}

	err = s.RemoveEntry(entry)
	if err != nil {
		log.Fatal(err)
	}
}

// open a password entry
func open(printPasswd bool) {
	var content string
	entry := subc.Sub("open").Arg(0)

	id, err := getIdentity()
	if err != nil {
		log.Fatalf("error parsing private key file: %s", err)
	}
	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("error parsing recipients file: %v", err)
	}
	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	passwd, err := s.ReadEntry(entry)
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range strings.Split(string(passwd), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		content = content + line + "\n"
	}

	if printPasswd {
		fmt.Printf("%s\n", content)
		return
	}

	err = clip(content)
	if err != nil {
		log.Fatal(err)
	}
}

func openEditor(editor string, path string) error {
	// open $EDITOR on the tempfile
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return err
	}
	err = cmd.Wait()
	if err != nil {
		return err
	}

	return nil
}

func edit(editor string) {
	entry := subc.Sub("edit").Arg(0)

	// setup store
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("error parsing private key file: %s", err)
	}
	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("error parsing recipients file: %v", err)
	}
	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	// create temporary file
	tmp, err := os.CreateTemp(os.TempDir(), tmpName)
	if err != nil {
		log.Fatalf("error creating temporary file: %v", err)
	}

	// when this function returns the file will be closed and removed
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	// does the entry exist?
	if _, err = os.Stat(storePath + "/" + entry); !os.IsNotExist(err) {
		var contentBuffer *bytes.Buffer
		// otherwise, copy the content to the tmpfile
		content, err := s.ReadEntry(entry)
		if err != nil {
			log.Fatalf("error during decryption: %v", err)
		}
		contentBuffer = bytes.NewBuffer(content)

		if _, err = io.Copy(tmp, contentBuffer); err != nil {
			log.Fatalf("error writing to temporary file: %v", err)
		}

	}

	openEditor(editor, tmp.Name())

	// overwrite the entry with the temporary file content
	tmpContent, err := os.ReadFile(tmp.Name())
	if err != nil {
		log.Fatal(err)
	}
	s.WriteEntry(entry, tmpContent)
}

func generate(length int) {
	entry := subc.Sub("gen").Arg(0)

	// setup store
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("error parsing private key file: %s", err)
	}
	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("error parsing recipients file: %v", err)
	}
	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	// create temporary file
	tmp, err := os.CreateTemp(os.TempDir(), tmpName)
	if err != nil {
		log.Fatalf("error creating temporary file: %v", err)
	}

	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if _, err = os.Stat(storePath + "/" + entry); os.IsNotExist(err) {
		contentBuffer := &bytes.Buffer{}

		// get (too many) random bytes
		randBytes := make([]byte, length)
		_, err := rand.Read(randBytes)
		if err != nil {
			log.Fatal(err)
		}

		encoder := base64.NewEncoder(base64.StdEncoding, contentBuffer)
		encoder.Write(randBytes)
		encoder.Close()

		// only copy length bytes (runes) to tmp
		if _, err = io.CopyN(tmp, contentBuffer, int64(length)); err != nil {
			log.Fatalf("error writing to temporary file: %v", err)
		}

	} else {
		log.Fatal(errors.New("entry already exists!"))
	}

	// overwrite the entry with the temporary file content
	tmpContent, err := os.ReadFile(tmp.Name())
	if err != nil {
		log.Fatal(err)
	}
	s.WriteEntry(entry, tmpContent)
}

func main() {
	log.SetFlags(0 | log.Lshortfile)
	//log.SetFlags(0)
	log.SetPrefix("page: ")

	var (
		editor      string
		length      int
		printPasswd bool
		force       bool
	)

	/*
		env vars
	*/

	configHome, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	dataHome, err := userDataDir()
	if err != nil {
		log.Fatal(err)
	}

	editor, ok := os.LookupEnv("EDITOR")
	if !ok {
		// default editor to 'vi'
		editor = "vi"
	}

	storePath = dataHome + "/page/secrets"
	recipientsPath = configHome + "/page/recipients"
	privateKeyPath = configHome + "/page/privkey"

	/*
		subcommands
	*/

	//subc.Usage = usage

	subc.Sub("help").Usage = func() {
		errPrint("help: show help\n")
	}
	subc.Sub("ls").Usage = func() {
		errPrint("ls: list all secrets\n")
		errPrint("usage: page ls\n")
	}
	subc.Sub("init").Usage = func() {
		errPrint("init: generate key pair\n")
		errPrint("usage: page init\n")
	}

	subc.Sub("edit").StringVar(&editor, "e", editor, "editor")
	subc.Sub("edit").Usage = func() {
		errPrint("edit: create/edit a secret\n")
		errPrint("usage: page edit [-e editor] <secret>\nwhere:\n")
		errPrint("  -e editor  specify editor to use instead of $EDITOR\n")
		errPrint("  <secret>   is the filename of the secret to edit\n")
	}

	subc.Sub("gen").StringVar(&editor, "e", editor, "editor")
	subc.Sub("gen").IntVar(&length, "l", 12, "length")
	subc.Sub("gen").Usage = func() {
		errPrint("gen: randomly generate a secret\n")
		errPrint("usage: page gen [-l length] <secret>\nwhere:\n")
		errPrint("  -l length  specify length of string to be generated\n")
		errPrint("  <secret>   is the filename of the secret to edit\n")
	}

	subc.Sub("rm").BoolVar(&force, "f", false, "force remove entry (do not prompt)")
	subc.Sub("rm").Usage = func() {
		errPrint("rm: delete a secret\n")
		errPrint("usage: page rm [-f] <secret>\nwhere:\n")
		errPrint("  -f        forces deletion (does not prompt)\n")
		errPrint("  <secret>  is the filename of the secret to remove\n")

	}

	subc.Sub("open").BoolVar(&printPasswd, "p", false, "copy/print password to stdout")
	subc.Sub("open").Usage = func() {
		errPrint("open: copy secret content to clipboard\n")
		errPrint("usage: page open [-p] <secret>\nwhere:\n")
		errPrint("  -p        prints the secret instead of adding to clipboard\n")
		errPrint("  <secret>  is the filename of the secret to remove\n")
	}

	subcommand, err := subc.Parse()
	if errors.Is(err, subc.ErrNoSubc) {
		usage()
		os.Exit(1)
	} else if errors.Is(err, subc.ErrUsage) {
		os.Exit(0)
	} else if err != nil {
		log.Fatal(err)
	}

	switch subcommand {
	case "help":
		usage()
	case "ls":
		list()
	case "init":
		initKeys()
	case "edit":
		edit(editor)
	case "gen":
		generate(length)
	case "rm":
		remove(force)
	case "open":
		open(printPasswd)
	default:
		errPrint("unknown command `%s'\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
