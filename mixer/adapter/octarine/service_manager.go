package octarine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.octarinesec.com/common/cache"
	"golang.octarinesec.com/common/clientsession"
	"golang.octarinesec.com/common/ginutils"
)

type ServiceManager struct {
	session         *clientsession.ClientSession
	url             clientsession.Url
	backendHostname string
	backendPort     string
	namespace       string
	artifactID      string
	deploymentID    string
	accessToken     string
	artifactCache   map[string]*cache.Cache // keys are namespaces
	deploymentCache map[string]*cache.Cache // keys are namespaces
}

type configObject struct {
	ID             string            `json:"id"`
	Group          string            `json:"group"`
	Member         string            `json:"member"`
	Lables         map[string]string `json:"labels"`
	IngressDefault string            `json:"ingressdefault"`
	EgressDefault  string            `json:"egressdefault"`
	Ns             string            `json:"ns"`
}

type artifacts []configObject
type deployments []configObject

func (m *ServiceManager) get(url string) ([]byte, error) {
	resp, err := m.session.Get(url)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to request object at %v: %v", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to request object with status code %v: %v",
			resp.StatusCode, ginutils.BodyOfSafe(resp))
	}

	body, err := ginutils.BodyBytes(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for %v with status code %v: %v",
			url, resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get results from %v with status code %v: %v",
			url, resp.StatusCode, string(body))
	}

	return body, nil
}

func (m *ServiceManager) populateCache() error {
	var url string
	var body []byte
	var err error

	// Populate artifacts
	url = m.url.MakeNsPath(m.namespace, "artifacts")

	body, err = m.get(url)
	arts := artifacts{}

	err = json.Unmarshal(body, &arts)
	if err != nil {
		return fmt.Errorf("failed to parse artifacts: %v", err)
	}

	if m.artifactCache == nil {
		m.artifactCache = make(map[string]*cache.Cache)
	}

	// If there's a current cache, overwrite it.
	artCache := cache.New("artifact_cache", 10*time.Minute, 1*time.Minute)

	for _, a := range arts {
		name := fmt.Sprintf("%s:%s", a.Group, a.Member)
		artCache.Put(name, true)
	}

	m.artifactCache[m.namespace] = artCache

	// Populate deployments
	url = m.url.MakeNsPath(m.namespace, "deployments")

	body, err = m.get(url)
	deps := deployments{}

	err = json.Unmarshal(body, &deps)
	if err != nil {
		return fmt.Errorf("failed to parse deployments: %v", err)
	}

	if m.deploymentCache == nil {
		m.deploymentCache = make(map[string]*cache.Cache)
	}

	// If there's a current cache, overwrite it.
	depCache := cache.New("deployment_cache", 10*time.Minute, 1*time.Minute)

	for _, d := range deps {
		name := fmt.Sprintf("%s:%s", d.Group, d.Member)
		depCache.Put(name, true)
	}

	m.deploymentCache[m.namespace] = depCache

	return nil
}

func (m *ServiceManager) initSession() error {
	var err error

	serviceName := fmt.Sprintf("%s@%s", m.artifactID, m.deploymentID)

	m.url = clientsession.Url{
		Scheme: "https",
		Host:   m.backendHostname,
		Port:   m.backendPort,
	}

	m.session, err = clientsession.CreateTokenSession(m.accessToken,
		m.namespace, serviceName, m.url, time.Second*10)
	if err != nil {
		return fmt.Errorf("failed to create client session for %v: %v", m.url.String(), err)
	}

	err = m.session.Login()
	if err != nil {
		return fmt.Errorf("Failed to login at %v: %v", m.url.String(), err)
	}

	if err = m.populateCache(); err != nil {
		return err
	}

	return nil
}

func (m *ServiceManager) createObject(name string, endpoint string) error {
	var url string
	var err error

	type objectBody struct {
		Name           string            `json:"name"`
		Lables         map[string]string `json:"labels"`
		IngressDefault string            `json:"ingressdefault"`
		EgressDefault  string            `json:"egressdefault"`
	}

	requestBody := objectBody{
		Name:           name,
		Lables:         make(map[string]string),
		IngressDefault: "allow",
		EgressDefault:  "allow",
	}

	url = m.url.MakeNsPath(m.namespace, endpoint)

	strval, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatal(err)
	}
	reqBody := bytes.NewBuffer(strval)

	log.Printf("Sending request to %s", url)
	resp, err := m.session.Post(url, reqBody)

	if err != nil {
		return fmt.Errorf("failed to create object '%s': %v", name, err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusConflict {
		body, err := ginutils.BodyBytes(resp)
		if err != nil {
			return fmt.Errorf("failed to create object '%s', status: %d",
				name, resp.StatusCode)
		}
		return fmt.Errorf("failed to create object '%s', status: %d: %s",
			name, resp.StatusCode, string(body))
	}

	return nil
}

func (m *ServiceManager) createArtifact(artifactName string) error {
	m.artifactCache[m.namespace].Put(artifactName, true)
	return m.createObject(artifactName, "artifacts")
}

func (m *ServiceManager) createDeployment(deploymentName string) error {
	m.deploymentCache[m.namespace].Put(deploymentName, true)
	return m.createObject(deploymentName, "deployments")
}

func (m *ServiceManager) ObserveInstance(serviceName string, instanceID string,
	version string, hostname string) error {
	log.Printf("Observed service %s\n", serviceName)
	elements := strings.Split(serviceName, "@")
	if len(elements) != 2 {
		return fmt.Errorf("service name is not in the correct format: %s", serviceName)
	}

	if _, ok := m.artifactCache[m.namespace].Get(elements[0]); !ok {
		if err := m.createArtifact(elements[0]); err != nil {
			return err
		}
	}

	if _, ok := m.deploymentCache[m.namespace].Get(elements[1]); !ok {
		if err := m.createDeployment(elements[1]); err != nil {
			return err
		}
	}

	return nil
}

func NewFromFile(gflagsFile string) (*ServiceManager, error) {
	m := ServiceManager{}

	if gflagsFile == "" {
		return nil, fmt.Errorf("no file provided for config")
	}

	file, err := os.Open(gflagsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		elements := strings.Split(line, "=")
		if len(elements) != 2 {
			continue
		}

		key := strings.TrimLeft(strings.TrimSpace(elements[0]), "-")
		value := elements[1]

		if key == "backend_hostname" {
			m.backendHostname = value
		}

		if key == "backend_port" {
			m.backendPort = value
		}

		if key == "backend_namespace" {
			m.namespace = value
		}

		if key == "artifact_id" {
			m.artifactID = value
		}

		if key == "deployment_id" {
			m.deploymentID = value
		}

		if key == "initial_access_token" {
			m.accessToken = value
		}
	}

	err = scanner.Err()

	if err != nil {
		return nil, err
	}

	if m.backendHostname == "" {
		return nil, fmt.Errorf("missing backend_hostname from file %s", gflagsFile)
	}

	if m.backendPort == "" {
		return nil, fmt.Errorf("missing backend_port from file %s", gflagsFile)
	}

	if m.namespace == "" {
		return nil, fmt.Errorf("missing backend_namespace from file %s", gflagsFile)
	}

	if m.artifactID == "" {
		return nil, fmt.Errorf("missing artifact_id from file %s", gflagsFile)
	}

	if m.deploymentID == "" {
		return nil, fmt.Errorf("missing deployment_id from file %s", gflagsFile)
	}

	if m.accessToken == "" {
		return nil, fmt.Errorf("missing initial_access_token from file %s", gflagsFile)
	}

	err = m.initSession()
	if err != nil {
		log.Panicf("error occurred during initialization: %v", err)
		return nil, err
	}

	return &m, nil
}
