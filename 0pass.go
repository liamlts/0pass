package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"time"

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

func passwordList() []string {
	passwords, err := ioutil.ReadDir("crypt/")
	if err != nil {
		log.Fatal(err)
	}

	var passlist []string

	for _, pass := range passwords {
		passlist = append(passlist, pass.Name())
	}

	for i := range passlist {
		passlist[i] = passlist[i][:len(passlist[i])-len(".data")]
	}
	return passlist
}

func makePass(strength int) []byte {
	var CharString = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#$%&")
	var leng int
	rand.Seed(time.Now().UnixNano())
	switch strength {
	case 1:
		leng = 9
	case 2:
		leng = 13
	case 3:
		leng = 17
	default:
		leng = 17
	}

	p := make([]byte, leng)
	for i := range p {
		p[i] = CharString[rand.Intn(len(CharString))]
	}
	return p
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
			Action: func(c *cli.Context) {
				var pass string
				filename := c.Args().Get(0)
				if filename == "" {
					fmt.Println("Error please specify a service.(ex. google, youtube, github")
					os.Exit(1)
				}
				fmt.Println("Getting password for: " + filename)
				fmt.Println("Please enter you master password:")
				fmt.Scanln(&pass)
				key := cryptog.GenKeySalt(pass, readSalt())
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
		{
			Name:  "list",
			Usage: "Shows list of all saved passwords.",
			Action: func(*cli.Context) {
				passwords := passwordList()
				fmt.Println("Password list")
				fmt.Println("----------------")

				for i := range passwords {
					fmt.Println(passwords[i])
				}

			},
		},
		{
			Name:  "genpass",
			Usage: "Generate a random secure password.",
			Action: func(*cli.Context) {
				var mpass string
				var filename string
				var stren int
				fmt.Printf("Enter your master password: \n")
				fmt.Scanln(&mpass)
				salt := readSalt()
				key := cryptog.GenKeySalt(mpass, salt)
				fmt.Println("Enter a strength level (1-3): ")
				fmt.Scanln(&stren)
				mpass = string(makePass(stren))
				fmt.Println("What service is this for: ")
				fmt.Scanln(&filename)

				cryptog.WriteToFile(filename, cryptog.Encrypt(key, mpass))
			},
		},
		{
			Name:  "help",
			Usage: "Man for 0pass",
			Action: func(*cli.Context) {
				fmt.Println("0pass -- simple, non-bloated password manager.")
				fmt.Println("Materpass sets the password for accessing all your encrypted passwords.")
				fmt.Println("All other commands will ask you for your masterpass to access your passwords.")
				fmt.Println("AES-256 is used the stronger your masterpass the better.")
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
