package broker

import (
	"fmt"
)

// enforceExecEnvelope checks that the task token's capability envelope
// permits the requested target and role. Returns nil if no task identity
// is present (legacy mode) or if the envelope allows the operation.
func enforceExecEnvelope(agent *MCPAgent, target, role string) error {
	if agent.TaskClaims == nil {
		return nil // legacy mode — no envelope to check
	}
	env := &agent.TaskClaims.Envelope
	if !env.ContainsTarget(target) {
		return fmt.Errorf("task envelope does not permit target %q", target)
	}
	if !env.ContainsRole(role) {
		return fmt.Errorf("task envelope does not permit role %q", role)
	}
	return nil
}

// enforceProxyEnvelope checks that the task token's capability envelope
// permits the requested HTTP service and method. Returns nil if no task
// identity is present (legacy mode) or if the envelope allows the operation.
func enforceProxyEnvelope(agent *MCPAgent, serviceName, method string) error {
	if agent.TaskClaims == nil {
		return nil
	}
	env := &agent.TaskClaims.Envelope
	if !env.ContainsService(serviceName) {
		return fmt.Errorf("task envelope does not permit service %q", serviceName)
	}
	if !env.ContainsMethod(method) {
		return fmt.Errorf("task envelope does not permit method %q", method)
	}
	return nil
}

// enforceFederationEnvelope checks that the task token's capability envelope
// permits the requested remote MCP server. Returns nil if no task identity
// is present (legacy mode) or if the envelope allows the operation.
func enforceFederationEnvelope(agent *MCPAgent, remoteName string) error {
	if agent.TaskClaims == nil {
		return nil
	}
	env := &agent.TaskClaims.Envelope
	if !env.ContainsRemote(remoteName) {
		return fmt.Errorf("task envelope does not permit remote %q", remoteName)
	}
	return nil
}
