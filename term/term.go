// terminal input processing

package term

import (
	"fmt"
	t "golang.org/x/crypto/ssh/terminal"
	"os"
)

const (
	passwdPrompt = "secret: "
)

// ask a y/n question. get a boolean back
func Ask(message string) (resp bool, err error) {
	fmt.Fprintf(os.Stderr, "%s ", message)

	// raw terminal
	oldstate, err := t.MakeRaw(0)
	if err != nil {
		return false, err
	}

	// read single char
	var in []byte = make([]byte, 1)
	os.Stdin.Read(in)

	// restore terminal
	t.Restore(0, oldstate)
	fmt.Fprintf(os.Stderr, "\n")

	if !(string(in[0]) == "y" || string(in[0]) == "Y") {
		return false, nil
	}

	return true, nil
}

// ask for the password
func AskPasswd() (secret []byte, err error) {
	fmt.Fprintf(os.Stderr, passwdPrompt)

	secret, err = t.ReadPassword(0)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "\n")
	return secret, nil
}
