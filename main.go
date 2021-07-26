package main

import (
	"bytes"
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

// TODO remove
const (
	RecipientsPath = "/home/zzz/etc/page/recipients"
	PrivateKeyPath = "/home/zzz/etc/page/privkey"
)

const (
	wslClipPath = "/mnt/c/Windows/system32/clip.exe"
	warnPrint   = "warning: will print password to standard output"
	defaultLen  = 16
)

var (
	storePath string
)

// wrapper for Fprintf to print to stdout
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

//
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

// list all password entries
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

// remove a password entry
func remove(force bool) {
	entryId := subc.Sub("rm").Arg(0)

	// create a new store
	s := store.Store{Path: storePath}

	ok, err := s.EntryExists(entryId)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		log.Fatalf("entry %s does not exist", entryId)
	}

	if !force {
		ch, err := term.Ask("remove entry " + entryId + "?")
		if err != nil {
			log.Fatal(err)
		}

		if !ch {
			errPrint("aborted.\n")
			return
		}
	}

	err = s.RemoveEntry(entryId)
	if err != nil {
		log.Fatal(err)
	}
}

// open a password entry
func open(printPasswd bool) {
	if printPasswd {
		errPrint("%s\n", warnPrint)
	}

	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("Error parsing recipients file: %v", err)
	}
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("Error parsing private key file: %s", err)
	}

	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	entry := subc.Sub("open").Arg(0)
	passwd, err := s.OpenEntry(entry)
	if err != nil {
		log.Fatal(err)
	}

	// ask for secret
	//secret, err := term.AskPasswd()
	//if err != nil {
	//	log.Fatal(err)
	//}

	if printPasswd {
		fmt.Printf("%s\n", string(passwd))
		return
	}

	err = clip(string(passwd))
	if err != nil {
		log.Fatal(err)
	}
}

func getRecipients() (*age.X25519Recipient, error) {
	var pubkey []byte
	pubkey, err := os.ReadFile(RecipientsPath)
	if err != nil {
		return nil, nil
	}
	return age.ParseX25519Recipient(string(pubkey))
}

func getIdentity() (*age.X25519Identity, error) {
	var privkey []byte
	privkey, err := os.ReadFile(PrivateKeyPath)
	if err != nil {
		return nil, nil
	}

	var strippedPrivkey string

	for _, line := range strings.Split(string(privkey), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line != "" {
			strippedPrivkey = line
		}
	}

	return age.ParseX25519Identity(strippedPrivkey)
}

func edit() error {
	entry := subc.Sub("edit").Arg(0)

	rec, err := getRecipients()
	if err != nil {
		log.Fatalf("Error parsing recipients file: %v", err)
	}
	id, err := getIdentity()
	if err != nil {
		log.Fatalf("Error parsing private key file: %s", err)
	}

	var contentBuffer *bytes.Buffer
	/// TODO
	// IF FILE DOES NOT EXIST CREATE IT
	// copy to decrypted to tmpfile
	// open $EDITOR on tmpfile
	// read tmpfile
	// re-encrypt tmpfile to overwrite entryfile

	s := store.Store{Path: storePath, Identity: id, Recipient: rec}

	tmp, err := os.CreateTemp(os.TempDir(), "page-*")
	if err != nil {
		log.Fatalf("Erro creating tempfile: %v", err)
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	if _, err = os.Stat(storePath + "/" + entry); os.IsNotExist(err) {
		// create file
		//_, err := os.Create(storePath + "/" + entry)
		//if err != nil {
		//	log.Fatal(err)
		//}

		contentBuffer = &bytes.Buffer{}

	} else {

		content, err := s.OpenEntry(entry)
		if err != nil {
			log.Fatalf("Error during decryption: %v", err)
		}
		contentBuffer = bytes.NewBuffer(content)

		if _, err = io.Copy(tmp, contentBuffer); err != nil {
			log.Fatalf("Error writing to tempfile: %v", err)
		}

	}

	cmd := exec.Command("vise", tmp.Name())
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

func main() {

	log.SetFlags(0 | log.Lshortfile)
	log.SetPrefix("page: ")

	// get default password store location
	configHome, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	defaultStore := configHome + "/page/secrets"
	storePath = defaultStore

	var (
		printPasswd bool
		force       bool
	)

	subc.Usage = usage

	subc.Sub("help")

	subc.Sub("ls").StringVar(&storePath, "s", defaultStore, "path to password store")
	subc.Sub("ls").Usage = func() {
		errPrint("list all entries in store\n")
		errPrint("usage: page ls [-s store]\n\n")
		errPrint("  -s store  use given password store\n")
	}

	subc.Sub("init").StringVar(&storePath, "s", defaultStore, "path to password store")

	subc.Sub("edit").StringVar(&storePath, "s", defaultStore, "path to password store")

	subc.Sub("rm").StringVar(&storePath, "s", defaultStore, "path to password store")
	subc.Sub("rm").BoolVar(&force, "f", false, "force remove entry (do not prompt)")
	subc.Sub("rm").Usage = func() {
		errPrint("remove a password entry\n")
		errPrint("usage: page rm [-f] [-s store] <user@site>\n\n")
		errPrint("    -f          force - do not prompt before removing")
		errPrint("    -s store    use password store")
	}

	subc.Sub("open").StringVar(&storePath, "s", defaultStore, "path to password store")
	subc.Sub("open").BoolVar(&printPasswd, "p", false, "print password to stdout")

	/*	subc.Sub("open").Usage = func() {
		errPrint("open a password entry\n")
		errPrint("usage: page open [-p] [-s store] [-k key_file] <user@site>\n\n")
		errPrint("  -p        print password to stdout\n")
		errPrint("  -s store  use password store\n")
		//errPrint("    -k key_file    supply key_file when using an encrypted store\n")
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
		edit()
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
