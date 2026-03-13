package broker

import (
	"context"
	"fmt"
	"time"

	"github.com/sprawl/clauth/internal/audit"
	"github.com/sprawl/clauth/internal/token"
)

// toolTaskCreate creates a new task with scoped identity and returns a CTT-E token.
func (s *MCPServer) toolTaskCreate(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available (signer does not support delegation)"), nil
	}

	description, ok := getStringArg(args, "description")
	if !ok || description == "" {
		return errorResult("description is required"), nil
	}

	ttlStr, _ := getStringArg(args, "ttl")
	if ttlStr == "" {
		ttlStr = "30m"
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid ttl: %v", err)), nil
	}
	if ttl > time.Hour {
		return errorResult("ttl cannot exceed 1h"), nil
	}
	if ttl <= 0 {
		return errorResult("ttl must be positive"), nil
	}

	// Build capability envelope from agent's RBAC permissions.
	s.broker.policyMu.RLock()
	envelope := BuildEnvelopeFromPolicy(agent.Name, s.broker.policyCfg)
	s.broker.policyMu.RUnlock()

	// Extract optional can_delegate flag.
	canDelegate := getBoolArg(args, "can_delegate", false)

	// Determine initiated_by based on auth method.
	namePrefix := agent.Name
	if len(namePrefix) > 6 {
		namePrefix = namePrefix[:6]
	}
	initiatedBy := fmt.Sprintf("clauth:apikey:ak_%s", namePrefix)

	// Create task in manager.
	task := s.broker.taskMgr.CreateTask(CreateTaskParams{
		AgentName:   agent.Name,
		Description: description,
		TTL:         ttl,
		InitiatedBy: initiatedBy,
		Envelope:    envelope,
		CanDelegate: canDelegate,
	})

	// Build token claims.
	claims := &token.TaskClaims{
		Subject: agent.Name,
		Task: token.TaskIdentity{
			ID:          task.ID,
			RootID:      task.RootID,
			ParentID:    task.ParentID,
			Depth:       task.Depth,
			Lineage:     task.Lineage,
			InitiatedBy: task.InitiatedBy,
			Description: task.Description,
		},
		Envelope: token.Envelope{
			Targets:  envelope.Targets,
			Roles:    envelope.Roles,
			Services: envelope.Services,
			Remotes:  envelope.Remotes,
			Methods:  envelope.Methods,
		},
		ExpiresAt: task.ExpiresAt,
	}

	// Sign CTT-E.
	tokenStr, err := s.broker.tokenIssuer.SignCTTE(claims)
	if err != nil {
		// Clean up task on signing failure.
		s.broker.taskMgr.RevokeTask(task.ID)
		return errorResult(fmt.Sprintf("failed to sign task token: %v", err)), nil
	}

	// Update metrics.
	s.broker.metrics.TasksCreated.Add(1)
	s.broker.metrics.TasksActive.Add(1)
	s.broker.metrics.TokensSigned.Add(1)

	// Audit log.
	s.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "task_create",
		Agent:     agent.Name,
		Details: map[string]string{
			"task_id":      task.ID,
			"description":  description,
			"ttl":          ttl.String(),
			"initiated_by": initiatedBy,
			"targets":      fmt.Sprintf("%v", envelope.Targets),
		},
	})

	// Return token and task info.
	result := map[string]interface{}{
		"task_id":      task.ID,
		"token":        tokenStr,
		"expires_at":   task.ExpiresAt.Format(time.RFC3339),
		"ttl_seconds":  int(ttl.Seconds()),
		"can_delegate": canDelegate,
		"envelope": map[string]interface{}{
			"targets":  envelope.Targets,
			"roles":    envelope.Roles,
			"services": envelope.Services,
			"remotes":  envelope.Remotes,
			"methods":  envelope.Methods,
		},
	}
	return jsonResult(result)
}

// toolTaskInfo returns information about a specific task or lists all agent tasks.
func (s *MCPServer) toolTaskInfo(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available"), nil
	}

	taskID, hasID := getStringArg(args, "task_id")

	if hasID && taskID != "" {
		task := s.broker.taskMgr.GetTask(taskID)
		if task == nil {
			return errorResult("task not found or expired"), nil
		}
		if task.AgentName != agent.Name {
			return errorResult("access denied: task belongs to another agent"), nil
		}

		remaining := time.Until(task.ExpiresAt)
		result := map[string]interface{}{
			"task":          task,
			"remaining_ttl": remaining.Round(time.Second).String(),
			"is_revoked":    s.broker.revocation.IsRevoked(task.ID),
		}
		return jsonResult(result)
	}

	// No task_id -- list all tasks for this agent.
	tasks := s.broker.taskMgr.ListTasksByAgent(agent.Name)
	return jsonResult(map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
	})
}

// toolTaskRevoke revokes a task and invalidates all its tokens via watermark.
func (s *MCPServer) toolTaskRevoke(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available"), nil
	}

	taskID, ok := getStringArg(args, "task_id")
	if !ok || taskID == "" {
		return errorResult("task_id is required"), nil
	}

	task := s.broker.taskMgr.GetTask(taskID)
	if task == nil {
		return errorResult("task not found or expired"), nil
	}
	if task.AgentName != agent.Name {
		return errorResult("access denied: task belongs to another agent"), nil
	}

	// Set watermark for cascading revocation.
	s.broker.revocation.Revoke(taskID)
	s.broker.metrics.WatermarkRevocations.Add(1)

	// Remove from task manager.
	s.broker.taskMgr.RevokeTask(taskID)
	s.broker.metrics.TasksActive.Add(-1)

	s.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityWarn,
		EventType: "task_revoke",
		Agent:     agent.Name,
		Details: map[string]string{
			"task_id":     taskID,
			"description": task.Description,
		},
	})

	return jsonResult(map[string]interface{}{
		"revoked": taskID,
		"status":  "all tokens invalidated",
	})
}

// parseEnvelopeArg extracts a TaskEnvelope from an untyped map argument.
// Returns nil if the key is absent or not a map. Returns an error if present but malformed.
func parseEnvelopeArg(args map[string]interface{}, key string) (*TaskEnvelope, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	env := &TaskEnvelope{}
	if targets, ok := m["targets"]; ok {
		arr, ok := targets.([]interface{})
		if !ok {
			return nil, fmt.Errorf("envelope.targets must be an array")
		}
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("envelope.targets items must be strings")
			}
			env.Targets = append(env.Targets, s)
		}
	}
	if roles, ok := m["roles"]; ok {
		arr, ok := roles.([]interface{})
		if !ok {
			return nil, fmt.Errorf("envelope.roles must be an array")
		}
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("envelope.roles items must be strings")
			}
			env.Roles = append(env.Roles, s)
		}
	}
	if services, ok := m["services"]; ok {
		arr, ok := services.([]interface{})
		if !ok {
			return nil, fmt.Errorf("envelope.services must be an array")
		}
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("envelope.services items must be strings")
			}
			env.Services = append(env.Services, s)
		}
	}
	if remotes, ok := m["remotes"]; ok {
		arr, ok := remotes.([]interface{})
		if !ok {
			return nil, fmt.Errorf("envelope.remotes must be an array")
		}
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("envelope.remotes items must be strings")
			}
			env.Remotes = append(env.Remotes, s)
		}
	}
	if methods, ok := m["methods"]; ok {
		arr, ok := methods.([]interface{})
		if !ok {
			return nil, fmt.Errorf("envelope.methods must be an array")
		}
		for _, item := range arr {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("envelope.methods items must be strings")
			}
			env.Methods = append(env.Methods, s)
		}
	}
	return env, nil
}

// toolTaskDelegate creates a child task with attenuated capabilities and returns a CTT-D token.
func (s *MCPServer) toolTaskDelegate(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available (signer does not support delegation)"), nil
	}

	parentTaskID, ok := getStringArg(args, "parent_task_id")
	if !ok || parentTaskID == "" {
		return errorResult("parent_task_id is required"), nil
	}

	description, ok := getStringArg(args, "description")
	if !ok || description == "" {
		return errorResult("description is required"), nil
	}

	ttlStr, _ := getStringArg(args, "ttl")
	if ttlStr == "" {
		ttlStr = "10m"
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid ttl: %v", err)), nil
	}
	if ttl <= 0 {
		return errorResult("ttl must be positive"), nil
	}

	// Parse optional envelope.
	envelope, err := parseEnvelopeArg(args, "envelope")
	if err != nil {
		return errorResult(fmt.Sprintf("invalid envelope: %v", err)), nil
	}

	canDelegate := getBoolArg(args, "can_delegate", false)

	// Create child task.
	child, err := s.broker.taskMgr.CreateChildTask(CreateChildTaskParams{
		ParentID:    parentTaskID,
		AgentName:   agent.Name,
		Description: description,
		TTL:         ttl,
		Envelope:    envelope,
		CanDelegate: canDelegate,
	})
	if err != nil {
		return errorResult(fmt.Sprintf("delegation failed: %v", err)), nil
	}

	// Build token claims from child task.
	claims := &token.TaskClaims{
		Subject: agent.Name,
		Task: token.TaskIdentity{
			ID:          child.ID,
			RootID:      child.RootID,
			ParentID:    child.ParentID,
			Depth:       child.Depth,
			Lineage:     child.Lineage,
			InitiatedBy: child.InitiatedBy,
			Description: child.Description,
		},
		Envelope: token.Envelope{
			Targets:  child.Envelope.Targets,
			Roles:    child.Envelope.Roles,
			Services: child.Envelope.Services,
			Remotes:  child.Envelope.Remotes,
			Methods:  child.Envelope.Methods,
		},
		ExpiresAt: child.ExpiresAt,
	}

	// Sign CTT-D.
	tokenStr, err := s.broker.tokenIssuer.SignCTTD(claims)
	if err != nil {
		s.broker.taskMgr.RevokeTask(child.ID)
		return errorResult(fmt.Sprintf("failed to sign delegation token: %v", err)), nil
	}

	// Update metrics.
	s.broker.metrics.TasksCreated.Add(1)
	s.broker.metrics.TasksActive.Add(1)
	s.broker.metrics.TokensSigned.Add(1)
	s.broker.metrics.TokensDelegated.Add(1)

	// Audit log.
	s.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "task_delegate",
		Agent:     agent.Name,
		Details: map[string]string{
			"parent_task_id": parentTaskID,
			"child_task_id":  child.ID,
			"description":    description,
			"ttl":            ttl.String(),
			"depth":          fmt.Sprintf("%d", child.Depth),
		},
	})

	// Return child task info and token.
	result := map[string]interface{}{
		"task_id":        child.ID,
		"parent_task_id": parentTaskID,
		"token":          tokenStr,
		"expires_at":     child.ExpiresAt.Format(time.RFC3339),
		"depth":          child.Depth,
		"can_delegate":   canDelegate,
		"envelope": map[string]interface{}{
			"targets":  child.Envelope.Targets,
			"roles":    child.Envelope.Roles,
			"services": child.Envelope.Services,
			"remotes":  child.Envelope.Remotes,
			"methods":  child.Envelope.Methods,
		},
	}
	return jsonResult(result)
}

// toolTaskList lists all active tasks for the requesting agent.
func (s *MCPServer) toolTaskList(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available"), nil
	}

	tasks := s.broker.taskMgr.ListTasksByAgent(agent.Name)

	type taskSummary struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
		ExpiresAt   string `json:"expires_at"`
		Remaining   string `json:"remaining_ttl"`
		IsRevoked   bool   `json:"is_revoked"`
	}

	summaries := make([]taskSummary, 0, len(tasks))
	for _, t := range tasks {
		summaries = append(summaries, taskSummary{
			ID:          t.ID,
			Description: t.Description,
			CreatedAt:   t.CreatedAt.Format(time.RFC3339),
			ExpiresAt:   t.ExpiresAt.Format(time.RFC3339),
			Remaining:   time.Until(t.ExpiresAt).Round(time.Second).String(),
			IsRevoked:   s.broker.revocation.IsRevoked(t.ID),
		})
	}

	return jsonResult(map[string]interface{}{
		"tasks": summaries,
		"count": len(summaries),
	})
}

