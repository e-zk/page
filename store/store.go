package store

import (
	"bytes"
	"errors"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// errors
var (
	ErrEntryExists   = errors.New("entry already exists")
	ErrEntryNotExist = errors.New("entry does not exist")
)

// secret store struct
type Store struct {
	Path      string
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// secret entry struct (file)
type Entry struct {
	Path string
}

// return list of secrets in store
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

// write content to encrypted secret
func (s Store) WriteEntry(entry string, content []byte) error {
	entryPath := s.Path + "/" + entry

	err := os.WriteFile(entryPath, []byte{}, 0644)
	if err != nil {
		return err
	}

	fp, err := os.OpenFile(entryPath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		fp.Close()
		// make sure the entry has locked-down perms
		os.Chmod(entryPath, 0644)
	}()

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

// read content from encrypted secret
func (s Store) ReadEntry(entry string) (content []byte, err error) {
	ok, err := s.EntryExists(entry)
	if err != nil {
		return []byte{}, err
	}
	if !ok {
		return []byte{}, ErrEntryNotExist
	}

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

// check if a secret exists within a store
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
	ok, err := s.EntryExists(entry)
	if err != nil {
		return err
	}
	if !ok {
		return ErrEntryNotExist
	}

	// remove file
	err = os.Remove(s.Path + "/" + entry)
	if err != nil {
		return err
	}

	return nil
}
