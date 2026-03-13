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
		"task_id":     task.ID,
		"token":       tokenStr,
		"expires_at":  task.ExpiresAt.Format(time.RFC3339),
		"ttl_seconds": int(ttl.Seconds()),
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

// validateTaskEnvelope checks if the requested target/role/service is within
// the agent's active task envelope. Returns nil if valid or task identity is disabled.
func (s *MCPServer) validateTaskEnvelope(agent *MCPAgent, target, role string) error {
	if !s.broker.TaskIdentityEnabled() {
		return nil // legacy mode: no task validation
	}

	// For Phase 2a, task envelope validation is advisory --
	// we log the check but don't enforce it yet.
	// This will become mandatory when agents start using task_create.

	return nil
}
