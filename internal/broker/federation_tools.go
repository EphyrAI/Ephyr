package broker

import (
	"strings"
)

// FederatedToolDefinitions returns tool definitions from all connected remotes,
// with names prefixed as "{prefix}.{toolName}".
// Disconnected/errored remotes still return tools but with "[OFFLINE] " prepended to description.
func (f *MCPFederator) FederatedToolDefinitions() []MCPToolDefinition {
	if f == nil {
		return nil
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var tools []MCPToolDefinition
	for _, state := range f.remotes {
		state.mu.RLock()
		enabled := state.Config.Enabled
		prefix := f.prefix(state)
		offline := state.Status != RemoteStatusConnected
		cached := state.Tools
		state.mu.RUnlock()

		// Skip disabled remotes entirely -- do not expose their tools.
		if !enabled {
			continue
		}

		for _, tool := range cached {
			fedTool := MCPToolDefinition{
				Name:        prefix + "." + tool.Name,
				Description: tool.Description,
				InputSchema: tool.InputSchema,
			}
			if offline {
				fedTool.Description = "[OFFLINE] " + fedTool.Description
			}
			tools = append(tools, fedTool)
		}
	}

	if tools == nil {
		tools = []MCPToolDefinition{}
	}
	return tools
}

// FederatedResources returns resources from all connected remotes,
// with URIs transformed: "original://uri" becomes "remote:{prefix}://uri"
func (f *MCPFederator) FederatedResources() []MCPResource {
	if f == nil {
		return nil
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	var resources []MCPResource
	for _, state := range f.remotes {
		state.mu.RLock()
		prefix := f.prefix(state)
		cached := state.Resources
		state.mu.RUnlock()

		for _, res := range cached {
			// Transform URI: "original://path" -> "remote:{prefix}://path"
			// We split on "://" to extract the path portion, then rebuild.
			transformedURI := "remote:" + prefix + "://" + uriPath(res.URI)

			fedRes := MCPResource{
				URI:         transformedURI,
				Name:        prefix + ": " + res.Name,
				Description: res.Description,
				MimeType:    res.MimeType,
			}
			resources = append(resources, fedRes)
		}
	}

	if resources == nil {
		resources = []MCPResource{}
	}
	return resources
}

// IsFederatedTool returns true if the tool name contains a dot and the prefix
// matches a registered remote name.
func (f *MCPFederator) IsFederatedTool(name string) bool {
	if f == nil {
		return false
	}

	dotIdx := strings.IndexByte(name, '.')
	if dotIdx < 0 {
		return false
	}

	prefix := name[:dotIdx]

	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, state := range f.remotes {
		state.mu.RLock()
		p := f.prefix(state)
		state.mu.RUnlock()
		if p == prefix {
			return true
		}
	}

	return false
}

// ParseFederatedTool splits "weather.get_forecast" into ("weather", "get_forecast", true).
// Only the FIRST dot is the separator. "remote.some.tool" -> ("remote", "some.tool").
// Returns ("", "", false) if the name doesn't match any registered remote.
func (f *MCPFederator) ParseFederatedTool(name string) (remoteName, toolName string, ok bool) {
	if f == nil {
		return "", "", false
	}

	dotIdx := strings.IndexByte(name, '.')
	if dotIdx < 0 {
		return "", "", false
	}

	prefix := name[:dotIdx]
	tool := name[dotIdx+1:]

	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, state := range f.remotes {
		state.mu.RLock()
		p := f.prefix(state)
		rName := state.Config.Name
		state.mu.RUnlock()
		if p == prefix {
			return rName, tool, true
		}
	}

	return "", "", false
}

// IsFederatedResource returns true if URI starts with "remote:" prefix.
func (f *MCPFederator) IsFederatedResource(uri string) bool {
	if f == nil {
		return false
	}
	return strings.HasPrefix(uri, "remote:")
}

// ParseFederatedResource splits "remote:weather://current" into ("weather", "weather://current", true).
// The format is "remote:{prefix}://{path}" -> remoteName=prefix, originalURI="{prefix}://{path}"
func (f *MCPFederator) ParseFederatedResource(uri string) (remoteName, originalURI string, ok bool) {
	if f == nil {
		return "", "", false
	}

	if !strings.HasPrefix(uri, "remote:") {
		return "", "", false
	}

	// Strip the "remote:" prefix to get "{prefix}://{path}"
	rest := uri[len("remote:"):]

	// Split on "://" to extract the prefix (which is the scheme portion).
	sepIdx := strings.Index(rest, "://")
	if sepIdx < 0 {
		return "", "", false
	}

	prefix := rest[:sepIdx]
	// The original URI is the rest after "remote:", i.e., "{prefix}://{path}"
	originalURI = rest

	// Validate that this prefix matches a registered remote.
	f.mu.RLock()
	defer f.mu.RUnlock()

	for _, state := range f.remotes {
		state.mu.RLock()
		p := f.prefix(state)
		rName := state.Config.Name
		state.mu.RUnlock()
		if p == prefix {
			return rName, originalURI, true
		}
	}

	return "", "", false
}

// uriPath extracts the path portion after "://" from a URI.
// If no "://" is found, returns the original string.
func uriPath(uri string) string {
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return uri
	}
	return uri[idx+3:]
}

// getState returns the RemoteMCPState for a named remote, or nil if not found.
func (f *MCPFederator) getState(name string) *RemoteMCPState {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.remotes[name]
}
