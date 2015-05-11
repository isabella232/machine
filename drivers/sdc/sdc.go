package sdc

import (
	"fmt"

	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/provider"
	"github.com/docker/machine/state"
	"github.com/docker/machine/utils"
	"os/exec"
	"path"

	log "github.com/Sirupsen/logrus"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"time"
)

const (
	driverName             = "sdc"
	SDCDockerPort   string = "2376"
	SDCDockerDomain string = "docker.joyent.com"
)

type Driver struct {
	Region      string
	Account     string
	PrivateKey  string
	MachineName string
	SSHUser     string
	SSHPort     int
	storePath   string
}

func init() {
	drivers.Register(driverName, &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "sdc-region",
			Usage:  "SDC data center (DC)",
			Value:  "us-east-3b",
			EnvVar: "SDC_REGION",
		},
		cli.StringFlag{
			Name:   "sdc-account",
			Usage:  "SDC Account",
			Value:  "",
			EnvVar: "SDC_ACCOUNT",
		},
		cli.StringFlag{
			Name:   "sdc-key",
			Usage:  "SDC SSH key",
			Value:  "",
			EnvVar: "SDC_KEY",
		},
	}
}

func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	return &Driver{
		MachineName: machineName,
		storePath:   storePath,
	}, nil
}


/* --------------------------------------------------------- */
/* Implement the drivers.Driver interface.                   */
/* --------------------------------------------------------- */

// AuthorizePort authorizes a port for machine access
func (d *Driver) AuthorizePort(ports []*drivers.Port) error {
	return nil
}
	
// Create a host using the driver's config
func (d *Driver) Create() error {
	return d.GenerateCertificates()
}

// DeauthorizePort removes a port for machine access
func (d *Driver) DeauthorizePort(ports []*drivers.Port) error {
	return nil
}

// DriverName returns the name of the driver as it is registered
func (d *Driver) DriverName() string {

	/* Overriding the driver name to avoid SSH provisioning - issue #886 */

	return "none";
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	return fmt.Sprintf("%s.%s", d.Region, SDCDockerDomain), nil
}

// GetMachineName returns the name of the machine
func (d *Driver) GetMachineName() string {
	return d.MachineName
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	// TODO: Anything better here?
	return d.GetIP()
}

// GetSSHPort returns port for use with ssh
func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

// GetSSHUsername returns username for use with ssh
func (d *Driver) GetSSHUsername() string {
	return d.Account
}

// GetSSHKeyPath returns key path for use with ssh
func (d *Driver) GetSSHKeyPath() string {
	return path.Join(d.storePath, "id_rsa")
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	return fmt.Sprintf("tcp://%s.%s:%s", d.Region, SDCDockerDomain, SDCDockerPort), nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	cert, err := tls.LoadX509KeyPair(path.Join(d.storePath, "cert.pem"), path.Join(d.storePath, "key.pem"))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}
	ip, _ := d.GetIP()

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/_ping", ip, SDCDockerPort))
	if err != nil {
		return state.Error, nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if string(body[:]) == "OK" {
		return state.Running, nil
	}
	return state.None, nil
}

// GetProviderType returns whether the instance is local/remote
func (d *Driver) GetProviderType() provider.ProviderType {
	return provider.Remote
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	return nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	return nil
}

// Restart a host. This may just call Stop(); Start() if the provider does not
// have any special restart behaviour.
func (d *Driver) Restart() error {
	return nil
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.Region = flags.String("sdc-region")
	d.Account = flags.String("sdc-account")
	d.PrivateKey = flags.String("sdc-key")

	if d.Account == "" {
		return fmt.Errorf("Please specify account")
	}
	if d.PrivateKey == "" {
		return fmt.Errorf("Please specify keyId")
	}
	return nil
}

// Start a host
func (d *Driver) Start() error {
	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	return nil
}

/* --------------------------------------------------------- */
/* End of driver.Driver                                      */
/* --------------------------------------------------------- */


/*
 * Download the certificate authority file from the sdc-docker server.
 */
func (d *Driver) DownloadCa() error {
	ip, _ := d.GetIP()
	url := fmt.Sprintf("https://%s:%s/ca.pem", ip, SDCDockerPort)
	log.Debugf("Downloading ca.pem file from %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	caFile := path.Join(utils.GetMachineDir(), d.MachineName, "ca.pem")
	out, err := os.Create(caFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)

	return err
}


/*
 * Generate the certificates (from the users private SSH key).
 *
 * This also generates the server*.pem certificate files, but there are
 * not used by sdc-docker (it just keeps machine happy).
 */
func (d *Driver) GenerateCertificates() error {
	err := d.DownloadCa()
	if err != nil {
		return err
	}

	log.Debugf("Generating openssl sdc-docker client certificates")

	var keyFile = path.Join(utils.GetMachineDir(), d.MachineName, "key.pem")
	var csrFile = path.Join(utils.GetMachineDir(), d.MachineName, "cert.csr")
	var certFile = path.Join(utils.GetMachineDir(), d.MachineName, "cert.pem")

	cmd := exec.Command("openssl", "rsa", "-in", d.PrivateKey, "-outform", "pem", "-out", keyFile)
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("openssl", "req", "-new", "-key", keyFile, "-out", csrFile, "-subj", "/CN=" + d.Account)
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("openssl", "x509", "-req", "-days", "365", "-in", csrFile, "-signkey", keyFile, "-out", certFile)
	err = cmd.Run()
	if err != nil {
		return err
	}

	log.Debugf("Generating server certificates")

	pemBytes, _ := ioutil.ReadFile(keyFile)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("ssh: no key found")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject: pkix.Name{
			CommonName: d.Account,
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return err
	}

	log.Debugf("writing server certificates")

	var serverKeyFile = path.Join(utils.GetMachineDir(), d.MachineName, "server-key.pem")
	var serverCertFile = path.Join(utils.GetMachineDir(), d.MachineName, "server.pem")

	certOut, _ := os.OpenFile(serverCertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certOut.Close()

	keyOut, _ := os.OpenFile(serverKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return nil
}
