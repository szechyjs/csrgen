package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v2"

	"github.com/AlecAivazis/survey"
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

func main() {

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

	if answers.Province == "-" {
		answers.Province = ""
	}
	if answers.Locality == "-" {
		answers.Locality = ""
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
			Help:    "Modern browsers only validate the URL aginst this list, be sure to include all applicable DNS entries.",
			Options: dnsOptions,
			Default: []string{answers.Hostname},
		}
		survey.AskOne(dnsPrompt, &dns, nil)

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
		CommonName:         answers.Hostname,
		Country:            []string{answers.Country},
		Province:           []string{answers.Province},
		Locality:           []string{answers.Locality},
		Organization:       []string{answers.Organization},
		OrganizationalUnit: []string{answers.OrganizationalUnit},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dns,
		IPAddresses:        ips,
	}

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

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
