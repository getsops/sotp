package main

import (
	"regexp"
	"testing"
	"time"

	"github.com/xlzd/gotp"
)

func TestAccountNameRe(t *testing.T) {
	accountNames := []struct {
		accountName string
		valid       bool
	}{
		{"foobar", true},
		{"foo-_bar", true},
		{"foo-bar-1337", true},
		{"foo=bar", false},
		{"foo*bar", false},
	}
	for _, testData := range accountNames {
		isValid := regexp.MustCompile(accountNameRe).MatchString(testData.accountName)
		if isValid && !testData.valid {
			t.Fatalf("account name %q passes regexp verification %q but was expected to fail", testData.accountName, accountNameRe)
		} else if !isValid && testData.valid {
			t.Fatalf("account name %q does not pass regexp verification %q but was expected to pass", testData.accountName, accountNameRe)
		}
	}
}

func TestDecryptConfig(t *testing.T) {
	cfg, err := decryptConfig("config.yaml")
	if err != nil {
		t.Fatal("failed to access configuration at 'config.yaml'", err)
	}
	if cfg.Accounts[0].Name != "test1" {
		t.Fatalf("expected account name `test1` but got %q", cfg.Accounts[0].Name)
	}
}

func TestGetTOTP(t *testing.T) {
	var testAwsMfaSecret = "YAGQP5IP77OO3HMPS3D2KPMSNLNDIB7EO22EGAN3JEGE3DAR37Z2U5YDGKGN44VA"
	otp := gotp.NewDefaultTOTP(testAwsMfaSecret)
	ts, err := time.Parse("2006-01-02", "2006-01-02")
	if err != nil {
		t.Fatal(err)
	}
	otpValue := otp.At(ts.Unix())
	if otpValue != "352864" {
		t.Fatalf("expected otp value 352864 but got %q", otpValue)
	}
}
