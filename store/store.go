// cpass/store
// this package describes the model of a password store as well as password
// entries

package store

import (
	"bytes"
	"errors"
	"filippo.io/age"
	"filippo.io/age/armor"
	"fmt"
	"io"
	"os"
)

const (
	jsonIndent = "  "
)

// Store errors
var (
	ErrStoreIsDir = errors.New("given path is a directory")
	ErrStoreExt   = errors.New("given store has incorrect extension")
	ErrStoreEnc   = errors.New("encrypted stores are not yet supported!")
)

// Entry errors
var (
	ErrEntryExists   = errors.New("entry already exists")
	ErrEntryNotExist = errors.New("entry does not exist")
)

// password store struct
type Store struct {
	Path      string
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// password entry struct
type Entry struct {
	Path string
}

// typedef a slice of entry structs
type Entries []string

// return list of bookmarks belonging to store
// list
func (s Store) Entries() (es []string, err error) {
	files, err := os.ReadDir(s.Path)
	if err != nil {
		return es, err
	}
	for _, f := range files {
		es = append(es, f.Name())
	}
	return es, nil
}

// write encrypt an entry file
func (s Store) WriteEntry(entry string, content []byte) error {
	fp, err := os.OpenFile(s.Path+"/"+entry, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	contentBuffer := bytes.NewBuffer(content)
	aw := armor.NewWriter(fp)

	w, err := age.Encrypt(aw, s.Recipient)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, contentBuffer); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}

	return nil
}

func (s Store) OpenEntry(entry string) (content []byte, err error) {
	enc, err := os.ReadFile(s.Path + "/" + entry)
	if err != nil {
		return []byte{}, err
	}
	f := bytes.NewBuffer(enc)

	out := &bytes.Buffer{}
	ar := armor.NewReader(f)

	r, err := age.Decrypt(ar, s.Identity)
	if err != nil {
		return []byte{}, err
	}

	if _, err := io.Copy(out, r); err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}

// check if an entry exists within a store
func (s Store) EntryExists(entry string) (exists bool, err error) {
	es, err := s.Entries()
	if err != nil {
		return false, err
	}

	for _, e := range es {
		if e == entry {
			return true, nil
		}
	}

	return false, nil
}

// delete a passwoard entry from a store
func (s Store) RemoveEntry(entry string) error {
	// get entries
	found, err := s.EntryExists(entry)
	if err != nil {
		return err
	}

	// not found
	if !found {
		return ErrEntryNotExist
	}

	// remove file
	err = os.Remove(s.Path + "/" + entry)
	if err != nil {
		return err
	}

	return nil
}

// generate password for password entry
//func (e Entry) GenPassword(secret []byte) string {
//	salt := fmt.Sprintf("%s@%s", e.Username, e.Url)
//	//return crypto.CryptoPass(secret, []byte(salt), e.Length)
//}

// output string representation of a list of bookmarks
func (es Entries) String() (out string) {
	for _, e := range es {
		out = fmt.Sprintf("%s%s\n", out, e)
	}
	return out
}

// from a list of password entries, find the one matching the given username + url
/*
func (es Entries) Get(givenId string) *Entry {
	//givenId := fmt.Sprintf("%s@%s", username, url)

	for _, e := range es {
		id := fmt.Sprintf("%s@%s", e.Username, e.Url)

		if id == givenId {
			return &e
		}
	}

	return nil
}
*/
