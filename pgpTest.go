package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// command to generatepublic key in desired format:  gpg --output public.pgp --export your@mail.com
const (
	publicKey = "public.pgp"
	helderKey = "helderPrivateKey.asc"
)

func main() {

	// source file
	sourceBytes, err := ioutil.ReadFile("a1.pdf")

	// destination file
	dst, err := os.Create("a5.pdf.gpg")
	if err != nil {
		panic(err)
	}
	defer dst.Close()

	//read public key
	entityKey, err := readEntity()
	if err != nil {
		fmt.Println(err)
	}

	// encrypt
	erro := encryptFile([]*openpgp.Entity{entityKey}, nil, sourceBytes, dst)

	if erro != nil {
		fmt.Println(erro)
	}

	// decrypt
	decryptFile()

}

func readEntity() (*openpgp.Entity, error) {
	f, err := os.Open(publicKey)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

func encryptFile(recip []*openpgp.Entity, signer *openpgp.Entity, r []byte, w io.Writer) error {
	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(helderKey)
	if err != nil {
		fmt.Println(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		fmt.Println(err)
	}
	entity = entityList[0]

	passphraseByte := []byte("XXXXXXXXXX")

	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	sourceText := string(r)
	wc, err := openpgp.Encrypt(w, recip, entity, &openpgp.FileHints{IsBinary: true}, nil)

	if err != nil {
		return err
	}

	if _, err := io.Copy(wc, strings.NewReader(sourceText)); err != nil {
		return err
	}

	return wc.Close()
}

func decryptFile() error {
	dst, err := os.Open("a6.pdf.sig")
	if err != nil {
		panic(err)
	}
	defer dst.Close()

	// init some vars
	var entityList openpgp.EntityList

	// Open the public key file
	keyringFileBuffer, err := os.Open(publicKey)
	if err != nil {
		fmt.Println(err)
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		fmt.Println(err)
	}

	md, err := openpgp.ReadMessage(dst, entityList, nil, nil)
	if err != nil {
		fmt.Println(err)
	}

	entity := md.SignedBy.Entity

	for key := range entity.Identities {
		fmt.Println("Key:", key)
	}

	ww, err := os.Create("a8.pdf")
	if err != nil {
		panic(err)
	}
	defer ww.Close()
	if _, err := io.Copy(ww, md.UnverifiedBody); err != nil {
		fmt.Println(err)
	}

	return nil
}

func signFile(input []byte, output io.Writer, myEntity *openpgp.Entity) error {
	if writeCloser, err := openpgp.Sign(output, myEntity, &openpgp.FileHints{IsBinary: true}, nil); err != nil {
		return err
	} else {
		writeCloser.Write(input)
		return writeCloser.Close()
	}
}
