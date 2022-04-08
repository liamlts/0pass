package cryptog

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/scrypt"
)

func GenKey(password string) ([]byte, []byte) {
	passwordbyte := []byte(password)
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Fatal(err)
	}

	pkey, err := scrypt.Key(passwordbyte, salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return pkey, salt
}

func GenKeySalt(password string, salt []byte) []byte {
	passwordbyte := []byte(password)
	key, err := scrypt.Key(passwordbyte, salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func Encrypt(key []byte, data string) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	databytes := []byte(data)
	hexdata := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, databytes, nil))
	return hexdata
}

func Decrypt(key []byte, data string) string {
	udata, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := []byte(udata)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return string(plaintext)
}

func exists() bool {
	_, err := os.Stat("crypt/")
	if err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	}
	return false
}

func WriteToFile(filename string, data string) {
	if !exists() {
		err := os.Mkdir("crypt", 0744)
		if err != nil {
			log.Fatal(err)
		}
	}

	file, err := os.OpenFile("crypt/"+filename+".data",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0744)
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	if _, err := file.WriteString(data + "\n"); err != nil {
		log.Fatal(err)
	}
}

func ReadFile(filename string) ([]string, error) {
	file, err := os.Open("crypt/" + filename + ".data")
	var data []string
	if err != nil {
		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		data = append(data, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return data, nil
}
