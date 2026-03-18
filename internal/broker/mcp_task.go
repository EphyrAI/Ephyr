package broker

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/EphyrAI/Ephyr/internal/audit"
	"github.com/EphyrAI/Ephyr/internal/macaroon"
	"github.com/EphyrAI/Ephyr/internal/token"
)

// isAncestor checks whether ancestorID appears in the given lineage slice.
// Lineage is ordered [root, ..., self], so an ancestor is any element in the
// lineage that is not the task itself.
func isAncestor(ancestorID string, lineage []string) bool {
	for _, id := range lineage {
		if id == ancestorID {
			return true
		}
	}
	return false
}

// filterToSubtree returns only the tasks whose lineage contains callerTaskID,
// or whose ID equals callerTaskID (i.e. the caller's own task and its descendants).
func filterToSubtree(tasks []*Task, callerTaskID string) []*Task {
	filtered := make([]*Task, 0, len(tasks))
	for _, t := range tasks {
		if t.ID == callerTaskID || isAncestor(callerTaskID, t.Lineage) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// decodeHolderPubKey extracts and base64url-decodes the holder_pub_key argument.
// Returns nil if the argument is absent or empty.
func decodeHolderPubKey(args map[string]interface{}) ([]byte, error) {
	keyStr, ok := getStringArg(args, "holder_pub_key")
	if !ok || keyStr == "" {
		return nil, nil
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid holder_pub_key: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid holder_pub_key: expected 32 bytes, got %d", len(keyBytes))
	}
	return keyBytes, nil
}

// toolTaskCreate creates a new task with scoped identity and returns a macaroon token.
// Falls back to JWT (CTT-E) if macaroon minting is not available.
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

	// P1 fix: if the agent authenticated with a task token (delegated macaroon
	// or JWT), constrain the new task's envelope to the INTERSECTION of the
	// policy-derived envelope and the presenting token's envelope. This prevents
	// a narrowly-scoped delegated token from minting a fresh full-scope token.
	if agent.TaskClaims != nil {
		presentingEnvelope := &TaskEnvelope{
			Targets:  agent.TaskClaims.Envelope.Targets,
			Roles:    agent.TaskClaims.Envelope.Roles,
			Services: agent.TaskClaims.Envelope.Services,
			Remotes:  agent.TaskClaims.Envelope.Remotes,
			Methods:  agent.TaskClaims.Envelope.Methods,
		}
		envelope = intersectEnvelopes(&envelope, presentingEnvelope)
	}

	// Extract optional can_delegate flag.
	canDelegate := getBoolArg(args, "can_delegate", false)

	// Extract optional holder_pub_key for Ephyr Bind.
	holderPubKey, err := decodeHolderPubKey(args)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	// Determine initiated_by based on auth method.
	namePrefix := agent.Name
	if len(namePrefix) > 6 {
		namePrefix = namePrefix[:6]
	}
	initiatedBy := fmt.Sprintf("ephyr:apikey:ak_%s", namePrefix)

	// Create task in manager.
	task := s.broker.taskMgr.CreateTask(CreateTaskParams{
		AgentName:    agent.Name,
		Description:  description,
		TTL:          ttl,
		InitiatedBy:  initiatedBy,
		Envelope:     envelope,
		CanDelegate:  canDelegate,
		HolderPubKey: holderPubKey,
	})

	// Determine default delegation depth.
	delegationDepth := 0
	if canDelegate {
		delegationDepth = DefaultMaxChildDepth
	}

	// Try macaroon minting first (v0.2b primary path).
	var tokenStr string
	var tokenType string
	if s.broker.macaroonMinter != nil {
		defer s.broker.metrics.ObserveTiming(&s.broker.metrics.MacaroonMintLatency)()

		macEnv := macaroon.EffectiveEnvelope{
			Targets:         envelope.Targets,
			Roles:           envelope.Roles,
			Services:        envelope.Services,
			Remotes:         envelope.Remotes,
			Methods:         envelope.Methods,
			CanDelegate:     canDelegate,
			DelegationDepth: delegationDepth,
			ExpiresAt:       task.ExpiresAt,
		}

		mac, mintErr := s.broker.macaroonMinter.MintRoot(task.ID, agent.Name, initiatedBy, macEnv)
		if mintErr != nil {
			s.broker.taskMgr.RevokeTask(task.ID)
			return errorResult(fmt.Sprintf("failed to mint macaroon: %v", mintErr)), nil
		}

		// Serialize: "mac_" + base64url(binary)
		macBytes, marshalErr := mac.MarshalBinary()
		if marshalErr != nil {
			s.broker.taskMgr.RevokeTask(task.ID)
			return errorResult(fmt.Sprintf("failed to serialize macaroon: %v", marshalErr)), nil
		}
		tokenStr = "mac_" + base64.RawURLEncoding.EncodeToString(macBytes)
		tokenType = "macaroon"

		// Register signature digest for task lookup during auth.
		sigDigest := sha256Hex(mac.Signature())
		task.MacaroonSigDigest = sigDigest
		s.broker.taskMgr.RegisterSignature(sigDigest, task.ID)

		// Macaroon-specific metrics.
		s.broker.metrics.MacaroonsMinted.Add(1)

		// Check size warning threshold.
		if len(macBytes) > macaroon.TokenSizeWarn {
			s.broker.metrics.TokenSizeWarnings.Add(1)
		}
	} else if s.broker.tokenIssuer != nil {
		// Fallback: JWT signing (legacy path during migration).
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

		jwtStr, jwtErr := s.broker.tokenIssuer.SignCTTE(claims)
		if jwtErr != nil {
			s.broker.taskMgr.RevokeTask(task.ID)
			return errorResult(fmt.Sprintf("failed to sign task token: %v", jwtErr)), nil
		}
		tokenStr = jwtStr
		tokenType = "jwt"
	} else {
		s.broker.taskMgr.RevokeTask(task.ID)
		return errorResult("no token minting backend available"), nil
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
			"token_type":   tokenType,
		},
	})

	if s.broker.eventHub != nil {
		s.broker.eventHub.Broadcast(Event{
			Type: "task_created",
			Data: map[string]interface{}{
				"task_id":      task.ID,
				"agent":        agent.Name,
				"description":  description,
				"depth":        0,
				"can_delegate": canDelegate,
			},
		})
	}

	// Return token and task info.
	result := map[string]interface{}{
		"task_id":      task.ID,
		"token":        tokenStr,
		"token_type":   tokenType,
		"expires_at":   task.ExpiresAt.Format(time.RFC3339),
		"ttl_seconds":  int(ttl.Seconds()),
		"can_delegate": canDelegate,
		"holder_bound": task.HolderBound,
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
			"holder_bound":  task.HolderBound,
		}
		if !task.BindDeadline.IsZero() {
			result["bind_deadline"] = task.BindDeadline.Format(time.RFC3339)
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

	// P1-3 fix: If authenticated via task token, can only revoke own task or descendants.
	// This prevents a child token from revoking its parent or sibling tasks.
	if agent.TaskClaims != nil {
		callerTaskID := agent.TaskClaims.Task.ID
		if taskID != callerTaskID {
			// Check if taskID is in the caller's subtree (caller is an ancestor)
			targetTask := s.broker.taskMgr.GetTask(taskID)
			if targetTask == nil || !isAncestor(callerTaskID, targetTask.Lineage) {
				return errorResult("access denied: can only revoke own task or descendants"), nil
			}
		}
	}

	// Set watermark for cascading revocation.
	s.broker.revocation.Revoke(taskID)
	s.broker.metrics.WatermarkRevocations.Add(1)

	// P1-4 fix: Only delete root key when revoking the ROOT task itself.
	// For non-root tasks, epoch watermarks handle revocation correctly.
	// Deleting the shared root key for a child revocation would invalidate
	// the parent, siblings, and all other descendants in the tree.
	if taskID == task.RootID {
		if s.broker.rootKeyStore != nil {
			s.broker.rootKeyStore.Delete(task.RootID)
		}
	}

	// Remove from task manager — also cascade to all children in the tree.
	children := s.broker.taskMgr.GetTaskTree(task.RootID)
	cascadeCount := 0
	for _, child := range children {
		if child.ID != taskID {
			// Check if this child is a descendant of the revoked task
			for _, ancestor := range child.Lineage {
				if ancestor == taskID {
					s.broker.revocation.Revoke(child.ID)
					s.broker.taskMgr.RevokeTask(child.ID)
					s.broker.metrics.TasksActive.Add(-1)
					cascadeCount++
					break
				}
			}
		}
	}
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

	if s.broker.eventHub != nil {
		s.broker.eventHub.Broadcast(Event{
			Type: "task_revoked",
			Data: map[string]interface{}{
				"task_id": taskID,
				"agent":   agent.Name,
			},
		})
	}

	return jsonResult(map[string]interface{}{
		"revoked":       taskID,
		"cascade_count": cascadeCount,
		"status":        "all tokens invalidated",
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

// toolTaskDelegate creates a child task with attenuated capabilities and returns
// a macaroon token. Falls back to JWT (CTT-D) if macaroon minting is not available.
// When the presenting agent authenticated with a macaroon, the child macaroon is
// derived from the parent's HMAC chain (true macaroon delegation).
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

	// P1-3 fix: If authenticated via task token, can only delegate from own task.
	// This prevents a child token from delegating from a sibling or parent task
	// that it shouldn't have access to.
	if agent.TaskClaims != nil {
		callerTaskID := agent.TaskClaims.Task.ID
		if parentTaskID != callerTaskID {
			return errorResult("access denied: can only delegate from your own task"), nil
		}
	}

	// P1 fix: if the agent authenticated with a task token, constrain the
	// requested child envelope to the presenting token's effective envelope.
	// The macaroon caveat reducer may have narrowed the envelope below the
	// parent task's stored envelope, so we must enforce attenuation against
	// what the presenting token actually permits, not just the parent task.
	if envelope != nil && agent.TaskClaims != nil {
		presentingEnvelope := &TaskEnvelope{
			Targets:  agent.TaskClaims.Envelope.Targets,
			Roles:    agent.TaskClaims.Envelope.Roles,
			Services: agent.TaskClaims.Envelope.Services,
			Remotes:  agent.TaskClaims.Envelope.Remotes,
			Methods:  agent.TaskClaims.Envelope.Methods,
		}
		constrained := intersectEnvelopes(envelope, presentingEnvelope)
		envelope = &constrained
	}

	// Create child task in the task manager (validates depth, TTL, envelope subset).
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

	// Determine delegation depth for the child macaroon.
	childDelegationDepth := 0
	if canDelegate {
		// The parent's remaining depth minus 1, bounded by DefaultMaxChildDepth.
		childDelegationDepth = DefaultMaxChildDepth - child.Depth
		if childDelegationDepth < 0 {
			childDelegationDepth = 0
		}
	}

	// Try macaroon delegation first.
	var tokenStr string
	var tokenType string
	if s.broker.macaroonMinter != nil && agent.RawMacaroon != nil {
		defer s.broker.metrics.ObserveTiming(&s.broker.metrics.MacaroonMintLatency)()

		childMacEnv := macaroon.EffectiveEnvelope{
			Targets:         child.Envelope.Targets,
			Roles:           child.Envelope.Roles,
			Services:        child.Envelope.Services,
			Remotes:         child.Envelope.Remotes,
			Methods:         child.Envelope.Methods,
			CanDelegate:     canDelegate,
			DelegationDepth: childDelegationDepth,
			ExpiresAt:       child.ExpiresAt,
		}

		childMac, mintErr := s.broker.macaroonMinter.MintDelegated(agent.RawMacaroon, childMacEnv)
		if mintErr != nil {
			s.broker.taskMgr.RevokeTask(child.ID)
			return errorResult(fmt.Sprintf("failed to mint delegated macaroon: %v", mintErr)), nil
		}

		macBytes, marshalErr := childMac.MarshalBinary()
		if marshalErr != nil {
			s.broker.taskMgr.RevokeTask(child.ID)
			return errorResult(fmt.Sprintf("failed to serialize delegated macaroon: %v", marshalErr)), nil
		}
		tokenStr = "mac_" + base64.RawURLEncoding.EncodeToString(macBytes)
		tokenType = "macaroon"

		// Register signature digest.
		sigDigest := sha256Hex(childMac.Signature())
		child.MacaroonSigDigest = sigDigest
		s.broker.taskMgr.RegisterSignature(sigDigest, child.ID)

		s.broker.metrics.MacaroonsMinted.Add(1)

		if len(macBytes) > macaroon.TokenSizeWarn {
			s.broker.metrics.TokenSizeWarnings.Add(1)
		}
	} else if s.broker.macaroonMinter != nil && agent.RawMacaroon == nil {
		// Agent authenticated via API key or JWT, but we can still mint a root macaroon
		// for the child (it becomes its own root in the macaroon HMAC chain).
		defer s.broker.metrics.ObserveTiming(&s.broker.metrics.MacaroonMintLatency)()

		childMacEnv := macaroon.EffectiveEnvelope{
			Targets:         child.Envelope.Targets,
			Roles:           child.Envelope.Roles,
			Services:        child.Envelope.Services,
			Remotes:         child.Envelope.Remotes,
			Methods:         child.Envelope.Methods,
			CanDelegate:     canDelegate,
			DelegationDepth: childDelegationDepth,
			ExpiresAt:       child.ExpiresAt,
		}

		childMac, mintErr := s.broker.macaroonMinter.MintRoot(
			child.RootID, agent.Name, child.InitiatedBy, childMacEnv,
		)
		if mintErr != nil {
			s.broker.taskMgr.RevokeTask(child.ID)
			return errorResult(fmt.Sprintf("failed to mint macaroon for delegated task: %v", mintErr)), nil
		}

		macBytes, marshalErr := childMac.MarshalBinary()
		if marshalErr != nil {
			s.broker.taskMgr.RevokeTask(child.ID)
			return errorResult(fmt.Sprintf("failed to serialize macaroon: %v", marshalErr)), nil
		}
		tokenStr = "mac_" + base64.RawURLEncoding.EncodeToString(macBytes)
		tokenType = "macaroon"

		sigDigest := sha256Hex(childMac.Signature())
		child.MacaroonSigDigest = sigDigest
		s.broker.taskMgr.RegisterSignature(sigDigest, child.ID)

		s.broker.metrics.MacaroonsMinted.Add(1)

		if len(macBytes) > macaroon.TokenSizeWarn {
			s.broker.metrics.TokenSizeWarnings.Add(1)
		}
	} else if s.broker.tokenIssuer != nil {
		// Fallback: JWT signing (legacy path).
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

		jwtStr, jwtErr := s.broker.tokenIssuer.SignCTTD(claims)
		if jwtErr != nil {
			s.broker.taskMgr.RevokeTask(child.ID)
			return errorResult(fmt.Sprintf("failed to sign delegation token: %v", jwtErr)), nil
		}
		tokenStr = jwtStr
		tokenType = "jwt"
	} else {
		s.broker.taskMgr.RevokeTask(child.ID)
		return errorResult("no token minting backend available"), nil
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
			"token_type":     tokenType,
		},
	})

	if s.broker.eventHub != nil {
		s.broker.eventHub.Broadcast(Event{
			Type: "task_delegated",
			Data: map[string]interface{}{
				"task_id":        child.ID,
				"parent_task_id": parentTaskID,
				"agent":          agent.Name,
				"description":    description,
				"depth":          child.Depth,
			},
		})
	}

	// Return child task info and token.
	result := map[string]interface{}{
		"task_id":        child.ID,
		"parent_task_id": parentTaskID,
		"token":          tokenStr,
		"token_type":     tokenType,
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

// toolTaskBind binds a holder public key to a delegated task for Ephyr Bind.
// The key must be provided within the task's bind deadline. This is the second
// phase of two-phase delegation key binding introduced in v0.3.2.
func (s *MCPServer) toolTaskBind(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if s.broker.taskMgr == nil {
		return errorResult("task identity not available"), nil
	}

	taskID, ok := getStringArg(args, "task_id")
	if !ok || taskID == "" {
		return errorResult("task_id is required"), nil
	}

	// Decode the public key.
	pubKey, err := decodeHolderPubKey(args)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	if pubKey == nil {
		return errorResult("holder_pub_key is required"), nil
	}

	// Verify the task belongs to this agent.
	task := s.broker.taskMgr.GetTask(taskID)
	if task == nil {
		return errorResult("task not found or expired"), nil
	}
	if task.AgentName != agent.Name {
		return errorResult("access denied: task belongs to another agent"), nil
	}

	// Bind the key.
	if err := s.broker.taskMgr.BindHolderKey(taskID, pubKey); err != nil {
		return errorResult(fmt.Sprintf("bind failed: %v", err)), nil
	}

	// Audit log.
	s.broker.auditLog.LogEvent(audit.AuditEvent{
		Severity:  audit.SeverityInfo,
		EventType: "task_bind",
		Agent:     agent.Name,
		Details: map[string]string{
			"task_id": taskID,
		},
	})

	// WebSocket broadcast.
	if s.broker.eventHub != nil {
		s.broker.eventHub.Broadcast(Event{
			Type: "task_bound",
			Data: map[string]interface{}{
				"task_id": taskID,
				"agent":   agent.Name,
			},
		})
	}

	return jsonResult(map[string]interface{}{
		"task_id":  taskID,
		"bound":   true,
		"bound_at": time.Now().Format(time.RFC3339),
	})
}

// toolTaskList lists all active tasks for the requesting agent.
func (s *MCPServer) toolTaskList(ctx context.Context, agent *MCPAgent, args map[string]interface{}) (*MCPToolsCallResult, error) {
	if !s.broker.TaskIdentityEnabled() {
		return errorResult("task identity not available"), nil
	}

	tasks := s.broker.taskMgr.ListTasksByAgent(agent.Name)

	// P1-3 fix: If authenticated via task token, only show own task and descendants.
	// This prevents a child token from enumerating sibling or parent tasks.
	if agent.TaskClaims != nil {
		callerTaskID := agent.TaskClaims.Task.ID
		tasks = filterToSubtree(tasks, callerTaskID)
	}

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
