package main

import (
	"bytes"
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

	"github.com/atotto/clipboard"
	"github.com/e-zk/subc"
	"github.com/e-zk/wslcheck"
)

const (
	wslClipPath = "/mnt/c/Windows/system32/clip.exe"
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
	errPrint("usage: page [command] [args]\n\n")
	errPrint("where [command] can be:\n")
	errPrint("  help  show this help message\n")
	errPrint("  ls    list password entries\n")
	errPrint("  open  open/view a password entry\n")
	errPrint("  save  save/add a new password entry\n")
	errPrint("  rm    remove password entry\n")
	errPrint("\n")
	errPrint("for help with subcommands type: page [command] -h\n")
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

// Read the recipient file and return an age.X25519Recipient
func getRecipients() (*age.X25519Recipient, error) {
	var pubkey []byte
	pubkey, err := os.ReadFile(recipientsPath)
	if err != nil {
		return nil, nil
	}
	return age.ParseX25519Recipient(string(pubkey))
}

// Read the private key and return an age.X25519Identity
func getIdentity() (*age.X25519Identity, error) {
	var privkey []byte
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
			errPrint("aborted.\n")
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

	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("Error parsing recipients file: %v", err)
	}
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("Error parsing private key file: %s", err)
	}
	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	passwd, err := s.ReadEntry(entry)
	if err != nil {
		log.Fatal(err)
	}

	// ask for secret
	//secret, err := term.AskPasswd()
	//if err != nil {
	//	log.Fatal(err)
	//}

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

func edit(editor string) error {
	var contentBuffer *bytes.Buffer
	entry := subc.Sub("edit").Arg(0)

	// setup store
	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("Error parsing recipients file: %v", err)
	}
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("Error parsing private key file: %s", err)
	}
	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	// create temporary file
	tmp, err := os.CreateTemp(os.TempDir(), "page-*")
	if err != nil {
		log.Fatalf("Error creating temporary file: %v", err)
	}

	// when this function returns the file will be closed and removed
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	// does the entry exist?
	if _, err = os.Stat(storePath + "/" + entry); os.IsNotExist(err) {
		// empty buffer, since the file has no content
		contentBuffer = &bytes.Buffer{}

	} else {
		// otherwise, copy the content to the tmpfile
		content, err := s.ReadEntry(entry)
		if err != nil {
			log.Fatalf("Error during decryption: %v", err)
		}
		contentBuffer = bytes.NewBuffer(content)

		if _, err = io.Copy(tmp, contentBuffer); err != nil {
			log.Fatalf("Error writing to temporary file: %v", err)
		}

	}

	// open $EDITOR on the tempfile
	cmd := exec.Command(editor, tmp.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	if err != nil {
		log.Fatal(err)
	}

	// overwrite the entry with the temporary file content
	tmpContent, err := os.ReadFile(tmp.Name())
	if err != nil {
		log.Fatal(err)
	}
	s.WriteEntry(entry, tmpContent)

	return nil
}

/*
func initialise() {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Failed to generate age key pair: %v", err)
	}
	//fmt.Fprintf(storePath+"/recipients", "%s", id.Recipient().String())
	//fmt.Fprintf(storePath+"/privkey", "%s", id.String())
	fmt.Fprintf(os.Stderr, "%s", id.Recipient().String())
	fmt.Fprintf(os.Stderr, "%s", id.String())
}
*/

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

func main() {
	log.SetFlags(0)
	//log.SetFlags(0 | log.Lshortfile)
	log.SetPrefix("page: ")

	var (
		editor      string
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
	// default to 'vi'
	if !ok {
		editor = "vi"
	}

	storePath = dataHome + "/page/secrets"
	recipientsPath = configHome + "/page/recipients"
	privateKeyPath = configHome + "/page/privkey"

	/*
		subcommands
	*/

	subc.Usage = usage

	subc.Sub("help")
	subc.Sub("ls")
	subc.Sub("init")
	subc.Sub("edit").StringVar(&editor, "e", editor, "editor")

	subc.Sub("rm").BoolVar(&force, "f", false, "force remove entry (do not prompt)")
	/*subc.Sub("rm").Usage = func() {
		errPrint("remove a password entry\n")
		errPrint("usage: page rm [-f] [-s store] <user@site>\n\n")
		errPrint("  -f        force - do not prompt before removing")
		errPrint("  -s store  use password store")
	}*/

	//subc.Sub("ls").Usage = func() {
	//	errPrint("list all entries in the store\n")
	//	errPrint("usage: page ls\n\n")
	//}

	subc.Sub("open").BoolVar(&printPasswd, "p", false, "print password to stdout")

	/*subc.Sub("open").Usage = func() {
		errPrint("copies a password entry to the clipboard.\n")
		errPrint("does not copy lines starting with '#'.\n")
		errPrint("usage: page open [-p] [-s store] <user@site>\n\n")
		errPrint("  -p        print password to stdout\n")
	}*/

	subcommand, err := subc.Parse()
	if err == subc.ErrNoSubc {
		usage()
		os.Exit(1)
	} else if err == subc.ErrUsage {
		os.Exit(0)
	} else if err != nil {
		log.Fatal(err)
	}

	switch subcommand {
	case "help":
		usage()
	//case "init":
	//	initialise()
	case "ls":
		list()
	case "edit":
		edit(editor)
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
