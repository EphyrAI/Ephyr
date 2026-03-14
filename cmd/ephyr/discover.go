package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ServiceInfo describes an HTTP proxy service (agent-facing, no credentials).
type ServiceInfo struct {
	Name           string   `json:"name"`
	URLPrefix      string   `json:"url_prefix"`
	AuthType       string   `json:"auth_type"`
	Description    string   `json:"description"`
	Enabled        *bool    `json:"enabled,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
}

// RemoteInfo describes a federated MCP server.
type RemoteInfo struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	Description     string `json:"description"`
	Enabled         bool   `json:"enabled"`
	Status          string `json:"status"`
	StatusMessage   string `json:"status_message,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	ServerVersion   string `json:"server_version,omitempty"`
	ToolCount       int    `json:"tool_count"`
	ResourceCount   int    `json:"resource_count"`
	AuthType        string `json:"auth_type"`
}

// ListServices returns all proxy services (credentials redacted).
func (c *BrokerClient) ListServices() ([]ServiceInfo, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/services", nil)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, readError(resp)
	}

	var result []ServiceInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("list services: decode: %w", err)
	}
	return result, nil
}

// ListRemotes returns all federated MCP servers.
func (c *BrokerClient) ListRemotes() ([]RemoteInfo, error) {
	if err := c.EnsureSession(); err != nil {
		return nil, err
	}

	resp, err := c.doRequest("GET", "/v1/remotes", nil)
	if err != nil {
		return nil, fmt.Errorf("list remotes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, readError(resp)
	}

	var result []RemoteInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("list remotes: decode: %w", err)
	}
	return result, nil
}

// cmdServices handles: ephyr services
func cmdServices(args []string) {
	fs := flag.NewFlagSet("services", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	client := NewBrokerClient(*socket, *configDir)
	services, err := client.ListServices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(services) == 0 {
		fmt.Println("No HTTP proxy services configured.")
		return
	}

	fmt.Printf("%-20s %-40s %-10s %-8s %s\n", "NAME", "URL PREFIX", "AUTH", "ENABLED", "DESCRIPTION")
	fmt.Printf("%-20s %-40s %-10s %-8s %s\n", "----", "----------", "----", "-------", "-----------")

	for _, s := range services {
		enabled := "yes"
		if s.Enabled != nil && !*s.Enabled {
			enabled = "no"
		}
		desc := s.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		methods := ""
		if len(s.AllowedMethods) > 0 {
			methods = " [" + strings.Join(s.AllowedMethods, ",") + "]"
		}
		fmt.Printf("%-20s %-40s %-10s %-8s %s%s\n", s.Name, s.URLPrefix, s.AuthType, enabled, desc, methods)
	}
}

// cmdRemotes handles: ephyr remotes
func cmdRemotes(args []string) {
	fs := flag.NewFlagSet("remotes", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "Broker socket path")
	configDir := fs.String("config-dir", defaultConfigDir(), "Config directory")
	_ = fs.Parse(args)

	client := NewBrokerClient(*socket, *configDir)
	remotes, err := client.ListRemotes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(remotes) == 0 {
		fmt.Println("No federated MCP servers configured.")
		return
	}

	fmt.Printf("%-20s %-40s %-12s %-6s %-8s %s\n", "NAME", "URL", "STATUS", "TOOLS", "ENABLED", "DESCRIPTION")
	fmt.Printf("%-20s %-40s %-12s %-6s %-8s %s\n", "----", "---", "------", "-----", "-------", "-----------")

	for _, r := range remotes {
		enabled := "yes"
		if !r.Enabled {
			enabled = "no"
		}
		desc := r.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-20s %-40s %-12s %-6d %-8s %s\n", r.Name, r.URL, r.Status, r.ToolCount, enabled, desc)
	}
}
