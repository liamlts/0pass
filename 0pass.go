package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"example.com/cryptog"

	"github.com/urfave/cli"
)

func saveSalt(salt []byte) {
	eKey := base64.StdEncoding.EncodeToString(salt)
	saltfile, err := os.OpenFile("salt.data",
		os.O_CREATE|os.O_WRONLY, 0744)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := saltfile.WriteString(eKey + "\n"); err != nil {
		log.Fatal(err)
	}
}

func readSalt() []byte {
	savedSalt, err := os.Open("salt.data")
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(savedSalt)

	var data []string

	for scanner.Scan() {
		data = append(data, scanner.Text())
	}

	var salt string
	for i := range data {
		salt = data[i]

	}
	dSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		log.Fatal(err)
	}
	return []byte(dSalt)
}

func main() {
	app := cli.NewApp()
	app.Name = "0pass"
	app.Usage = "A simple and non-bloated password manager."

	app.Commands = []cli.Command{
		{
			Name:  "masterpass",
			Usage: "Generate key and salt based on given password. This is your master password.",
			Action: func(*cli.Context) {
				var password string
				fmt.Println("Enter your master password. AND WRITE IT DOWN!")
				fmt.Scanln(&password)
				_, salt := cryptog.GenKey(password)
				saveSalt(salt)

			},
		},
		{
			Name:  "addpass",
			Usage: "Saves new password for given service using the master password.",
			Action: func(*cli.Context) {
				var filename string
				var mpass string
				fmt.Printf("Enter your master password: \n")
				fmt.Scanln(&mpass)
				salt := readSalt()
				key := cryptog.GenKeySalt(mpass, salt)
				fmt.Println("Enter site name of what the password is used for:")
				fmt.Scanln(&filename)

				var data string
				fmt.Println("Input your password:")
				fmt.Scanln(&data)
				cryptog.WriteToFile(filename, cryptog.Encrypt(key, data))

			},
		},
		{
			Name:  "getpass",
			Usage: "Gets your password based on service provided.",
			Action: func(*cli.Context) {
				var pass string
				fmt.Println("Please enter you master password:")
				fmt.Scanln(&pass)
				key := cryptog.GenKeySalt(pass, readSalt())
				fmt.Println("What service are you looking for:")
				var filename string
				fmt.Scanln(&filename)
				file, err := cryptog.ReadFile(filename)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("Your " + filename + " password: \n")

				for i := range file {
					fmt.Println(cryptog.Decrypt(key, file[i]))
				}
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}