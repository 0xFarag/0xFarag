// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed verify_bundle.py
var original []byte

//go:embed bootstrap.py
var bootstrap string

const originalHash = "afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303"

func dependency(name, variable string) (string, error) {
	target := os.Getenv(variable)
	if target == "" {
		path, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("cannot locate %s; set %s to its trusted absolute file path", name, variable)
		}
		target = path
	}
	if !filepath.IsAbs(target) {
		return "", fmt.Errorf("%s must identify an absolute executable path", variable)
	}
	stat, err := os.Stat(target)
	if err != nil || !stat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is unavailable: %s", name, target)
	}
	return target, nil
}

func run() (int, error) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("AuthzLedger recipient verifier preview for v1.5.0")
		fmt.Println("ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).")
		return 0, nil
	}
	if fmt.Sprintf("%x", sha256.Sum256(original)) != originalHash {
		return 2, errors.New("embedded recipient verifier digest mismatch")
	}
	python, err := dependency("python", "AUTHZLEDGER_PYTHON")
	if err != nil {
		return 2, err
	}
	openssl, err := dependency("openssl", "AUTHZLEDGER_OPENSSL")
	if err != nil {
		return 2, err
	}
	args := append([]string{"-I", "-B", "-c", bootstrap, openssl}, os.Args[1:]...)
	command := exec.Command(python, args...)
	command.Stdin = bytes.NewReader(original)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	err = command.Run()
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return exit.ExitCode(), nil
	}
	return 2, err
}

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
