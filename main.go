/*
csrgen - Tool for creating certificate signing requests (CSRs)
Copyright (C) 2023 Jared Szechy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"gopkg.in/yaml.v3"
)

// PrefValue -
type PrefValue struct {
	Default  string `yaml:"default"`
	Required bool   `yaml:"required"`
	Lock     bool   `yaml:"lock"`
}

// Preferences -
type Preferences struct {
	Country            PrefValue `yaml:"country"`
	Province           PrefValue `yaml:"province"`
	Locality           PrefValue `yaml:"locality"`
	Organization       PrefValue `yaml:"organization"`
	OrganizationalUnit PrefValue `yaml:"organizationalUnit"`
}

// Answers -
type Answers struct {
	Hostname           string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

func (p *Preferences) parseConfigFile(cfgFile string) error {
	data, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, p)
	if err != nil {
		return err
	}

	if p.Locality.Required && !p.Province.Required {
		return errors.New("Province must be required if Locality is required")
	}

	return nil
}

func createQuestion(name string, cfg PrefValue) *survey.Question {
	question := survey.Question{
		Name: name,
		Prompt: &survey.Input{
			Message: name,
			Default: cfg.Default,
		},
	}

	if cfg.Required {
		question.Validate = survey.Required
	}

	return &question
}

func createQuestions(p Preferences) []*survey.Question {
	qs := []*survey.Question{
		{
			Name:     "Hostname",
			Prompt:   &survey.Input{Message: "Hostname"},
			Validate: survey.Required,
		},
	}

	if !p.Country.Lock {
		qs = append(qs, createQuestion("Country", p.Country))
	}

	if !p.Province.Lock {
		qs = append(qs, createQuestion("Province", p.Province))
	}

	if !p.Locality.Lock {
		qs = append(qs, createQuestion("Locality", p.Locality))
	}

	if !p.Organization.Lock {
		qs = append(qs, createQuestion("Organization", p.Organization))
	}

	if !p.OrganizationalUnit.Lock {
		qs = append(qs, createQuestion("OrganizationalUnit", p.OrganizationalUnit))
	}

	return qs
}

func createAnswers(p Preferences) Answers {
	ans := Answers{}

	if p.Country.Lock {
		ans.Country = p.Country.Default
	}

	if p.Province.Lock {
		ans.Province = p.Province.Default
	}

	if p.Locality.Lock {
		ans.Locality = p.Locality.Default
	}

	if p.Organization.Lock {
		ans.Organization = p.Organization.Default
	}

	if p.OrganizationalUnit.Lock {
		ans.OrganizationalUnit = p.OrganizationalUnit.Default
	}

	return ans
}

func validHost(host string) bool {
	re, _ := regexp.Compile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	if re.MatchString(host) {
		return true
	}
	return false
}

func printCSR(csr x509.CertificateRequest) {
	fmt.Printf("\n")
	if csr.Subject.Country != nil && len(csr.Subject.Country[0]) > 0 {
		fmt.Printf("Country: %s\n", csr.Subject.Country[0])
	}
	if csr.Subject.Province != nil && len(csr.Subject.Province[0]) > 0 {
		fmt.Printf("State/Province: %s\n", csr.Subject.Province[0])
	}
	if csr.Subject.Locality != nil && len(csr.Subject.Locality[0]) > 0 {
		fmt.Printf("Locality: %s\n", csr.Subject.Locality[0])
	}
	if csr.Subject.Organization != nil && len(csr.Subject.Organization[0]) > 0 {
		fmt.Printf("Organization: %s\n", csr.Subject.Organization[0])
	}
	if csr.Subject.OrganizationalUnit != nil && len(csr.Subject.OrganizationalUnit[0]) > 0 {
		fmt.Printf("Organizational Unit : %s\n", csr.Subject.OrganizationalUnit[0])
	}
	if len(csr.Subject.CommonName) > 0 {
		fmt.Printf("Common Name: %s\n", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
		fmt.Println("\nSubject Alternative Names")
		for _, dns := range csr.DNSNames {
			fmt.Printf("DNS Name: %s\n", dns)
		}
		for _, ip := range csr.IPAddresses {
			fmt.Printf("IP Address: %s\n", ip)
		}
	}
}

var keyFile string

func init() {
	flag.StringVar(&keyFile, "key", "", "Existing key file")
}

func main() {
	fmt.Println("csrgen  Copyright (C) 2023  Jared Szechy")
	fmt.Println("This program comes with ABSOLUTELY NO WARRANTY")

	flag.Parse()

	prefs := Preferences{}

	err := prefs.parseConfigFile("csr.yml")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	qs := createQuestions(prefs)

	answers := createAnswers(prefs)

	err = survey.Ask(qs, &answers)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	dns := []string{}
	ips := []net.IP{}
	if validHost(answers.Hostname) {
		parts := strings.Split(answers.Hostname, ".")
		dnsOptions := []string{
			answers.Hostname,
			"www." + answers.Hostname,
			"*." + answers.Hostname,
			parts[0],
		}
		dnsPrompt := &survey.MultiSelect{
			Message: "Subject Alternative Names (SAN):",
			Help:    "Modern browsers only validate the URL against this list, be sure to include all applicable DNS entries.",
			Options: dnsOptions,
			Default: []string{answers.Hostname},
		}
		survey.AskOne(dnsPrompt, &dns, nil)

		moreDNS := true
		for moreDNS {
			dnsStr := ""
			adlDNSPrompt := &survey.Input{
				Message: "Additional Subject Alternative Names (SAN):",
				Help:    "Add blank entry when done.",
			}
			survey.AskOne(adlDNSPrompt, &dnsStr, nil)

			moreDNS = false
			if len(dnsStr) > 0 {
				dns = append(dns, dnsStr)
				moreDNS = true
			}
		}

		moreIPs := true
		for moreIPs {
			ipStr := ""
			ipPrompt := &survey.Input{
				Message: "IP Address SAN",
				Help:    "Add IP addresses to SANs one at a time. Add blank entry when done.",
			}
			survey.AskOne(ipPrompt, &ipStr, nil)

			moreIPs = false
			if len(ipStr) > 0 {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					ips = append(ips, ip)
					moreIPs = true
				}
			}
		}
	}

	subj := pkix.Name{
		CommonName: answers.Hostname,
		Country:    []string{answers.Country},
	}
	if answers.Province != "-" {
		subj.Province = []string{answers.Province}
	}
	if answers.Locality != "-" {
		subj.Locality = []string{answers.Locality}
	}
	if answers.Organization != "-" {
		subj.Organization = []string{answers.Organization}
	}
	if answers.OrganizationalUnit != "-" {
		subj.OrganizationalUnit = []string{answers.OrganizationalUnit}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dns,
		IPAddresses:        ips,
	}

	printCSR(template)

	var keyBytes *rsa.PrivateKey
	if keyFile != "" {
		pemBytes, err1 := ioutil.ReadFile(keyFile)
		if err1 != nil {
			panic(err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			panic(errors.New("no PEM block found"))
		}
		fmt.Printf("Block Type: %s\n", block.Type)
		keyBytes, err1 = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err1 != nil {
			panic(err1)
		}
	} else {
		keySize := ""
		keyPrompt := &survey.Select{
			Message: "Select a key size",
			Options: []string{"1024", "2048", "4096"},
			Default: "2048",
		}
		survey.AskOne(keyPrompt, &keySize, nil)
		keyInt, _ := strconv.Atoi(keySize)

		keyBytes, _ = rsa.GenerateKey(rand.Reader, keyInt)
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)

	csrFile, err := os.Create(answers.Hostname + ".csr")
	if err != nil {
		fmt.Printf("Failed to open csr file for writing: %s\n", err)
		return
	}
	csrOut := io.MultiWriter(csrFile, os.Stdout)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csrFile.Close()

	keyFile, err := os.Create(answers.Hostname + ".key")
	if err != nil {
		fmt.Printf("Failed to open key file for writing: %s\n", err)
		return
	}
	keyOut := io.MultiWriter(keyFile, os.Stdout)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	keyFile.Close()
}
