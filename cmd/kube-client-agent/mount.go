package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/prometheus/common/expfmt"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	mountSecretCmd = &cobra.Command{
		Use:     "mount --FLAGS",
		Short:   "Mount a secret with certs",
		Long:    "This command mouts the secret with valid certs signed by etcd-cert-signer-controller",
		PreRunE: validateMountSecretOpts,
		RunE:    runCmdMountSecret,
	}

	mountSecretOpts struct {
		commonName string
		assetsDir  string
	}
)

func validateMountSecretOpts(cmd *cobra.Command, args []string) error {
	if mountSecretOpts.commonName == "" {
		return fmt.Errorf("missing required flag: --commonname")
	}
	if mountSecretOpts.assetsDir == "" {
		return fmt.Errorf("missing required flag: --assetsdir")
	}
	return nil

}

func runCmdMountSecret(cmd *cobra.Command, args []string) error {
	return mountSecret()
}

// mount will secret will look for secret in the form of
// <profile>-<podFQDN>, where profile can be peer, server
// and metric and mount the certs as commonname.crt/commonname.key
// this will run as init container in etcd pod managed by CEO.
func mountSecret() error {
	var err error
	inClusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("error creating in cluster client config: %v", err)
	}

	client, err := kubernetes.NewForConfig(inClusterConfig)
	if err != nil {
		return fmt.Errorf("error creating client: %v", err)
	}

	duration := 10 * time.Second
	var s *v1.Secret
	// wait forever for success and retry every duration interval
	err = wait.PollInfinite(duration, func() (bool, error) {
		fmt.Println(requestOpts.commonName)
		s, err = client.CoreV1().Secrets("openshift-etcd").Get(getSecretName(mountSecretOpts.commonName), metav1.GetOptions{})
		if err != nil {
			glog.Errorf("error in getting secret %s/%s: %v", "openshift-etcd", getSecretName(mountSecretOpts.commonName), err)
			return false, err
		}
		err = ensureCertKeys(s.Data)
		if err != nil {
			return false, err
		}

		return true, nil

	})

	if err != nil {
		return err
	}

	// write out signed certificate to disk
	certFile := path.Join(mountSecretOpts.assetsDir, mountSecretOpts.commonName+".crt")
	if err := ioutil.WriteFile(certFile, s.Data["tls.crt"], 0644); err != nil {
		return fmt.Errorf("unable to write to %s: %v", certFile, err)
	}
	keyFile := path.Join(mountSecretOpts.assetsDir, mountSecretOpts.commonName+".key")
	if err := ioutil.WriteFile(keyFile, s.Data["tls.key"], 0644); err != nil {
		return fmt.Errorf("unable to write to %s: %v", keyFile, err)
	}
	if strings.HasPrefix(mountSecretOpts.commonName, "system:etcd-metric") {
		// we should use client metric certs
		crt := fmt.Sprintf("/etc/ssl/etcd/%s.crt", mountSecretOpts.commonName)
		key := fmt.Sprintf("/etc/ssl/etcd/%s.key", mountSecretOpts.commonName)
		if err := getMetrics(key, crt); err != nil {
			return fmt.Errorf("unable to get Metrics: %v", err)
		}
	}
	return nil
}

func getSecretName(commonName string) string {
	prefix := ""
	if strings.Contains(commonName, "peer") {
		prefix = "peer"
	}
	if strings.Contains(commonName, "server") {
		prefix = "server"
	}
	if strings.Contains(commonName, "metric") {
		prefix = "metric"
	}
	return prefix + "-" + strings.Split(commonName, ":")[2]
}

func ensureCertKeys(data map[string][]byte) error {
	if len(data["tls.crt"]) == 0 || len(data["tls.key"]) == 0 {
		return fmt.Errorf("invalid secret data")
	}
	return nil
}

func getMetrics(key string, crt string) error {
	caFile := "/etc/ssl/etcd/metric-ca.crt"
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return err
	}
	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	if err := ParseReader(client); err != nil {
		return err
	}
	return nil
}

func ParseReader(client *http.Client) error {
	var parser expfmt.TextParser

	etcdName := os.Getenv("ETCD_NAME")
	if etcdName == "" {
		return fmt.Errorf("environment variable ETCD_NAME has no value")
	}

	etcdCluster := os.Getenv("ETCD_INITIAL_CLUSTER")
	if etcdName == "" {
		return fmt.Errorf("environment variable ETCD_INITIAL_CLUSTER has no value")
	}

	target, err := parseDialTargetFromInitialCluster(etcdCluster, etcdName)
	if err != nil {
		return err
	}
	resp, err := client.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	metricFamilies, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return fmt.Errorf("reading text format failed: %v", err)
	}
	for _, mf := range metricFamilies {
		if *mf.Name == "etcd_network_peer_round_trip_time_seconds" {
			for _, metric := range mf.Metric {
				glog.Infof("data %s\n", *metric.Label[0].Value)
			}
		}
	}
	for _, mf := range metricFamilies {
		if *mf.Name == "etcd_server_id" {
			for _, metric := range mf.Metric {
				glog.Infof("data %s\n", *metric.Label[0].Value)
			}
		}
	}
	for _, mf := range metricFamilies {
		if *mf.Name == "etcd_network_peer_sent_bytes_total" {
			for _, metric := range mf.Metric {
				glog.Infof("bytes %s %.f\n", *metric.Label[0].Value, *metric.Counter.Value)
			}
		}
	}

	return nil
}

func parseDialTargetFromInitialCluster(initialCluster, name string) (string, error) {
	glog.Infof("parseDialTargetFromInitialCluster %s and %s", initialCluster, name)
	// instead of taking first we could randomly select.
	for _, memberMap := range strings.Split(initialCluster, ",") {
		member := strings.Split(memberMap, "=")
		glog.Infof("comparing %s wirh %s", member[0], name)
		if member[0] == name {
			continue
		}
		parsed, err := url.Parse(member[1])
		if err != nil {
			return "", err
		}
		host, _, err := net.SplitHostPort(string(parsed.Host))
		if err != nil {
			return "", err
		}
		client := fmt.Sprintf("%s://%s:%s", parsed.Scheme, string(host), "9979")
		if _, err := url.Parse(client); err == nil {
			return client, nil
		}
	}
	return "", fmt.Errorf("could not find target from %s", initialCluster)
}
