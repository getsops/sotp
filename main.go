package main

import (
	"fmt"
	"log"
	"os"

	"github.com/xlzd/gotp"
	"go.mozilla.org/sops/v3/decrypt"
)

type Config struct {
	Accounts []Account
}
type Account struct {
	Name       string
	TOTPSecret string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: sotp <account_name>")
		os.Exit(1)
	}
	var cfg Config
	err := decrypt.YamlFile("config.yaml", &cfg)
	if err != nil {
		log.Fatal(err)
	}
	var totpSecret string
	for _, account := range cfg.Accounts {
		if account.Name == os.Args[1] {
			totpSecret = account.TOTPSecret
		}
		if totpSecret != "" {
			break
		}
	}
	if totpSecret == "" {
		fmt.Println("no totp information found for account", os.Args[1])
	}
	otp := gotp.NewDefaultTOTP(totpSecret)

	fmt.Println("current one-time password is:", otp.Now())
}
