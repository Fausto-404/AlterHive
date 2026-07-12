// Package parser is responsible for parsing the configurations of the core and honeypot service
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Plugin holds optional LLM plugin configuration for a service.
type Plugin struct {
	OpenAISecretKey         string `yaml:"openAISecretKey"`
	Host                    string `yaml:"host"`
	LLMModel                string `yaml:"llmModel"`
	LLMProvider             string `yaml:"llmProvider"`
	Prompt                  string `yaml:"prompt"`
	InputValidationEnabled  bool   `yaml:"inputValidationEnabled"`
	InputValidationPrompt   string `yaml:"inputValidationPrompt"`
	OutputValidationEnabled bool   `yaml:"outputValidationEnabled"`
	OutputValidationPrompt  string `yaml:"outputValidationPrompt"`
	RateLimitEnabled        bool   `yaml:"rateLimitEnabled"`
	RateLimitRequests       int    `yaml:"rateLimitRequests"`
	RateLimitWindowSeconds  int    `yaml:"rateLimitWindowSeconds"`
}

// BeelzebubServiceConfiguration is the struct that contains the configurations of the honeypot service
type BeelzebubServiceConfiguration struct {
	Filename               string    `yaml:"-" json:"-"`
	ApiVersion             string    `yaml:"apiVersion"`
	Protocol               string    `yaml:"protocol"`
	Address                string    `yaml:"address"`
	Commands               []Command `yaml:"commands"`
	Tools                  []Tool    `yaml:"tools"`
	FallbackCommand        Command   `yaml:"fallbackCommand"`
	ServerVersion          string    `yaml:"serverVersion"`
	ServerName             string    `yaml:"serverName"`
	DeadlineTimeoutSeconds int       `yaml:"deadlineTimeoutSeconds"`
	PasswordRegex          string    `yaml:"passwordRegex"`
	Description            string    `yaml:"description"`
	Banner                 string    `yaml:"banner"`
	Plugin                 Plugin    `yaml:"plugin"`
	TLSCertPath            string    `yaml:"tlsCertPath"`
	TLSKeyPath             string    `yaml:"tlsKeyPath"`
	// TrustedProxies is a list of CIDRs (or bare IPs) of upstream proxies whose
	// X-Forwarded-For / X-Real-IP headers can be trusted. When empty, those
	// headers are ignored and the immediate TCP peer is used as source IP.
	TrustedProxies     []string     `yaml:"trustedProxies,omitempty" json:",omitempty"`
	TrustedProxiesNets []*net.IPNet `yaml:"-" json:"-"`
}

func (bsc BeelzebubServiceConfiguration) HashCode() (string, error) {
	data, err := json.Marshal(bsc)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// Command is the struct that contains the configurations of the commands
type Command struct {
	RegexStr   string         `yaml:"regex"`
	Regex      *regexp.Regexp `yaml:"-"` // This field is parsed, not stored in the config itself.
	Handler    string         `yaml:"handler"`
	Headers    []string       `yaml:"headers"`
	StatusCode int            `yaml:"statusCode"`
	Plugin     string         `yaml:"plugin"`
	Name       string         `yaml:"name"`
}

// Tool is the struct that contains the configurations of the MCP Honeypot
type Tool struct {
	Name        string           `yaml:"name" json:"Name"`
	Description string           `yaml:"description" json:"Description"`
	Params      []Param          `yaml:"params" json:"Params"`
	Handler     string           `yaml:"handler" json:"Handler"`
	Annotations *ToolAnnotations `yaml:"annotations,omitempty" json:"Annotations,omitempty"`
}

// ToolAnnotations contains MCP tool annotation hints for LLM clients
type ToolAnnotations struct {
	Title           string `yaml:"title,omitempty" json:"Title,omitempty"`
	ReadOnlyHint    *bool  `yaml:"readOnlyHint,omitempty" json:"ReadOnlyHint,omitempty"`
	DestructiveHint *bool  `yaml:"destructiveHint,omitempty" json:"DestructiveHint,omitempty"`
	IdempotentHint  *bool  `yaml:"idempotentHint,omitempty" json:"IdempotentHint,omitempty"`
	OpenWorldHint   *bool  `yaml:"openWorldHint,omitempty" json:"OpenWorldHint,omitempty"`
}

// Param is the struct that contains the configurations of the parameters of the tools
type Param struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type configurationsParser struct {
	configurationsServicesDirectory    string
	readFileBytesByFilePathDependency  ReadFileBytesByFilePath
	gelAllFilesNameByDirNameDependency GelAllFilesNameByDirName
}

type ReadFileBytesByFilePath func(filePath string) ([]byte, error)

type GelAllFilesNameByDirName func(dirName string) ([]string, error)

// Init Parser, return a configurationsParser and use the D.I. Pattern to inject the dependencies
func Init(_, configurationsServicesDirectory string) *configurationsParser {
	return &configurationsParser{
		configurationsServicesDirectory:    configurationsServicesDirectory,
		readFileBytesByFilePathDependency:  readFileBytesByFilePath,
		gelAllFilesNameByDirNameDependency: gelAllFilesNameByDirName,
	}
}

// ReadConfigurationsServices reads honeypot service configurations.
// If the BEELZEBUB_SERVICES_CONFIG environment variable is set (JSON array), it is used directly.
// Otherwise, service YAML files are loaded from the configured directory.
func (bp configurationsParser) ReadConfigurationsServices() ([]BeelzebubServiceConfiguration, error) {
	if envConfig := os.Getenv("BEELZEBUB_SERVICES_CONFIG"); envConfig != "" {
		return parseServicesFromEnv(envConfig)
	}

	services, err := bp.gelAllFilesNameByDirNameDependency(bp.configurationsServicesDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warnf("Services config directory %q not found, falling back to empty configuration", bp.configurationsServicesDirectory)
			return []BeelzebubServiceConfiguration{}, nil
		}
		return nil, fmt.Errorf("in directory %s: %v", bp.configurationsServicesDirectory, err)
	}

	var servicesConfiguration []BeelzebubServiceConfiguration

	for _, servicesName := range services {
		filePath := filepath.Join(bp.configurationsServicesDirectory, servicesName)
		buf, err := bp.readFileBytesByFilePathDependency(filePath)
		if err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

		svc := &BeelzebubServiceConfiguration{}
		if err = yaml.Unmarshal(buf, svc); err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

		svc.Filename = servicesName

		if svc.Plugin.RateLimitEnabled {
			if svc.Plugin.RateLimitRequests <= 0 || svc.Plugin.RateLimitWindowSeconds <= 0 {
				return nil, fmt.Errorf("in file %s: invalid rate limiting config", filePath)
			}
		}

		if err := svc.CompileCommandRegex(); err != nil {
			return nil, fmt.Errorf("in file %s: invalid regex: %v", filePath, err)
		}

		if err := svc.CompileTrustedProxies(); err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

		log.Debug(svc)
		servicesConfiguration = append(servicesConfiguration, *svc)
	}

	return servicesConfiguration, nil
}

func parseServicesFromEnv(jsonStr string) ([]BeelzebubServiceConfiguration, error) {
	var services []BeelzebubServiceConfiguration
	if err := json.Unmarshal([]byte(jsonStr), &services); err != nil {
		return nil, fmt.Errorf("invalid BEELZEBUB_SERVICES_CONFIG: %v", err)
	}

	for i := range services {
		svc := &services[i]
		svc.Filename = fmt.Sprintf("<env:BEELZEBUB_SERVICES_CONFIG>[%d]", i)

		if svc.Plugin.RateLimitEnabled {
			if svc.Plugin.RateLimitRequests <= 0 || svc.Plugin.RateLimitWindowSeconds <= 0 {
				return nil, fmt.Errorf("invalid rate limiting config in BEELZEBUB_SERVICES_CONFIG[%d]", i)
			}
		}

		if err := svc.CompileCommandRegex(); err != nil {
			return nil, fmt.Errorf("invalid regex in BEELZEBUB_SERVICES_CONFIG[%d]: %v", i, err)
		}

		if err := svc.CompileTrustedProxies(); err != nil {
			return nil, fmt.Errorf("in BEELZEBUB_SERVICES_CONFIG[%d]: %v", i, err)
		}
	}

	return services, nil
}

// CompileCommandRegex is the method that compiles the regular expression for each configured Command.
func (c *BeelzebubServiceConfiguration) CompileCommandRegex() error {
	for i, command := range c.Commands {
		if command.RegexStr != "" {
			rex, err := regexp.Compile(command.RegexStr)
			if err != nil {
				return err
			}
			c.Commands[i].Regex = rex
		}
	}
	return nil
}

// CompileTrustedProxies parses the TrustedProxies entries (CIDRs or bare IPs)
// into net.IPNet values stored in TrustedProxiesNets. Bare IPs are treated as
// /32 (IPv4) or /128 (IPv6).
func (c *BeelzebubServiceConfiguration) CompileTrustedProxies() error {
	nets := make([]*net.IPNet, 0, len(c.TrustedProxies))
	for _, entry := range c.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return fmt.Errorf("invalid trustedProxies entry %q", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid trustedProxies entry %q: %v", entry, err)
		}
		nets = append(nets, n)
	}
	c.TrustedProxiesNets = nets
	return nil
}

func gelAllFilesNameByDirName(dirName string) ([]string, error) {
	files, err := os.ReadDir(dirName)
	if err != nil {
		return nil, err
	}

	var filesName []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yaml") {
			filesName = append(filesName, file.Name())
		}
	}
	return filesName, nil
}

func readFileBytesByFilePath(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
