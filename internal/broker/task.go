package broker

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ben-spanswick/ephyr/internal/policy"
	"github.com/ben-spanswick/ephyr/internal/token"
)

// Task represents an active agent task run with scoped identity.
type Task struct {
	ID          string       `json:"id"`           // ULID
	RootID      string       `json:"root_id"`      // ULID of the root task
	ParentID    string       `json:"parent_id"`    // empty for root tasks
	AgentName   string       `json:"agent_name"`
	Description string       `json:"description"`
	Depth       int          `json:"depth"`        // 0 = root
	Lineage     []string     `json:"lineage"`      // [root, ..., self]
	InitiatedBy string       `json:"initiated_by"` // "ephyr:local:uid:1000" etc.
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	Envelope    TaskEnvelope `json:"envelope"`
	TokenID     string       `json:"token_id"`     // JTI of the CTT-E
	CanDelegate       bool         `json:"can_delegate"`                  // whether CTT-D was issued (Phase 2b)
	MacaroonSigDigest string       `json:"macaroon_sig_digest,omitempty"` // SHA-256(macaroon signature)
}

// TaskEnvelope defines the maximum capabilities for a task.
type TaskEnvelope struct {
	Targets  []string `json:"targets"`
	Roles    []string `json:"roles"`
	Services []string `json:"services"`
	Remotes  []string `json:"remotes"`
	Methods  []string `json:"methods"`
}

// CreateTaskParams holds parameters for creating a new task.
type CreateTaskParams struct {
	AgentName   string
	Description string
	TTL         time.Duration
	InitiatedBy string
	Envelope    TaskEnvelope
	CanDelegate bool
}

// TaskManager tracks active tasks with thread-safe operations.
type TaskManager struct {
	mu       sync.RWMutex
	tasks    map[string]*Task           // task ID -> task
	byAgent  map[string]map[string]bool // agent name -> set of task IDs
	sigIndex map[string]string          // SHA-256(macaroon_signature) -> task ID
	stopCh   chan struct{}
	OnExpire func(*Task) // called when a task expires during cleanup
}

// NewTaskManager creates a TaskManager and starts a background cleanup
// goroutine that removes expired tasks every 30 seconds.
func NewTaskManager() *TaskManager {
	tm := &TaskManager{
		tasks:    make(map[string]*Task),
		byAgent:  make(map[string]map[string]bool),
		sigIndex: make(map[string]string),
		stopCh:   make(chan struct{}),
	}
	go tm.cleanupLoop()
	return tm
}

// Stop halts the background cleanup goroutine.
func (tm *TaskManager) Stop() {
	select {
	case <-tm.stopCh:
		// already stopped
	default:
		close(tm.stopCh)
	}
}

// CreateTask registers a new root task. The task manager generates the ID
// (ULID), sets lineage to [self], depth to 0, and timestamps.
func (tm *TaskManager) CreateTask(params CreateTaskParams) *Task {
	now := time.Now()
	id := token.NewULID()

	task := &Task{
		ID:          id,
		RootID:      id,
		ParentID:    "",
		AgentName:   params.AgentName,
		Description: params.Description,
		Depth:       0,
		Lineage:     []string{id},
		InitiatedBy: params.InitiatedBy,
		CreatedAt:   now,
		ExpiresAt:   now.Add(params.TTL),
		Envelope:    params.Envelope,
		CanDelegate: params.CanDelegate,
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.tasks[id] = task
	if tm.byAgent[params.AgentName] == nil {
		tm.byAgent[params.AgentName] = make(map[string]bool)
	}
	tm.byAgent[params.AgentName][id] = true

	return task
}

// GetTask retrieves a task by ID. Returns nil if not found or expired.
func (tm *TaskManager) GetTask(id string) *Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	task, ok := tm.tasks[id]
	if !ok {
		return nil
	}
	if time.Now().After(task.ExpiresAt) {
		return nil
	}
	return task
}

// ListTasks returns all active (non-expired) tasks, optionally filtered by
// agent name. If agentName is empty, all active tasks are returned.
// Results are sorted by creation time (oldest first).
func (tm *TaskManager) ListTasks(agentName string) []*Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	now := time.Now()
	var result []*Task

	if agentName != "" {
		ids := tm.byAgent[agentName]
		for id := range ids {
			if task, ok := tm.tasks[id]; ok && now.Before(task.ExpiresAt) {
				result = append(result, task)
			}
		}
	} else {
		for _, task := range tm.tasks {
			if now.Before(task.ExpiresAt) {
				result = append(result, task)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// ListTasksByAgent returns active tasks for a specific agent.
func (tm *TaskManager) ListTasksByAgent(agentName string) []*Task {
	return tm.ListTasks(agentName)
}

// RevokeTask removes a task and returns it. Returns nil if not found.
func (tm *TaskManager) RevokeTask(id string) *Task {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	task, ok := tm.tasks[id]
	if !ok {
		return nil
	}

	delete(tm.tasks, id)
	if agents, ok := tm.byAgent[task.AgentName]; ok {
		delete(agents, id)
		if len(agents) == 0 {
			delete(tm.byAgent, task.AgentName)
		}
	}
	if task.MacaroonSigDigest != "" {
		delete(tm.sigIndex, task.MacaroonSigDigest)
	}

	return task
}

// IsTaskActive returns true if the task exists and hasn't expired.
func (tm *TaskManager) IsTaskActive(id string) bool {
	return tm.GetTask(id) != nil
}

// RegisterSignature maps a macaroon signature digest to a task ID.
// Called when minting a new macaroon for a task.
func (tm *TaskManager) RegisterSignature(sigDigest string, taskID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.sigIndex[sigDigest] = taskID
}

// LookupBySignature returns the task for a macaroon signature digest.
// Returns nil if not found.
func (tm *TaskManager) LookupBySignature(sigDigest string) *Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	taskID, ok := tm.sigIndex[sigDigest]
	if !ok {
		return nil
	}
	task, exists := tm.tasks[taskID]
	if !exists {
		return nil
	}
	// Check expiry
	if time.Now().After(task.ExpiresAt) {
		return nil
	}
	return task
}

// UnregisterSignature removes a signature mapping.
func (tm *TaskManager) UnregisterSignature(sigDigest string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.sigIndex, sigDigest)
}

// TaskCount returns the number of active (non-expired) tasks.
func (tm *TaskManager) TaskCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, task := range tm.tasks {
		if now.Before(task.ExpiresAt) {
			count++
		}
	}
	return count
}

// GetChildren returns all active (non-expired) tasks whose ParentID matches
// the given parentID. Results are sorted by CreatedAt ascending.
// Returns an empty slice (not nil) if no children are found.
func (tm *TaskManager) GetChildren(parentID string) []*Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	now := time.Now()
	result := make([]*Task, 0)

	for _, task := range tm.tasks {
		if task.ParentID == parentID && now.Before(task.ExpiresAt) {
			result = append(result, task)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// GetTaskTree returns all active (non-expired) tasks belonging to a root tree
// (where RootID == rootID), including the root task itself.
// Results are sorted by Depth ascending, then CreatedAt ascending for same depth.
// Returns an empty slice if no tasks are found.
func (tm *TaskManager) GetTaskTree(rootID string) []*Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	now := time.Now()
	result := make([]*Task, 0)

	for _, task := range tm.tasks {
		if task.RootID == rootID && now.Before(task.ExpiresAt) {
			result = append(result, task)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Depth != result[j].Depth {
			return result[i].Depth < result[j].Depth
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// CountDelegations returns the count of active (non-expired) tasks with Depth > 0.
func (tm *TaskManager) CountDelegations() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, task := range tm.tasks {
		if task.Depth > 0 && now.Before(task.ExpiresAt) {
			count++
		}
	}
	return count
}

// ListAllTasks returns all active (non-expired) tasks regardless of agent,
// sorted by CreatedAt descending (newest first). Useful for dashboard global
// task views.
func (tm *TaskManager) ListAllTasks() []*Task {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	now := time.Now()
	result := make([]*Task, 0)

	for _, task := range tm.tasks {
		if now.Before(task.ExpiresAt) {
			result = append(result, task)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result
}

// cleanup removes expired tasks from the manager.
func (tm *TaskManager) cleanup() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	for id, task := range tm.tasks {
		if now.After(task.ExpiresAt) {
			if tm.OnExpire != nil {
				tm.OnExpire(task)
			}
			delete(tm.tasks, id)
			if agents, ok := tm.byAgent[task.AgentName]; ok {
				delete(agents, id)
				if len(agents) == 0 {
					delete(tm.byAgent, task.AgentName)
				}
			}
			if task.MacaroonSigDigest != "" {
				delete(tm.sigIndex, task.MacaroonSigDigest)
			}
		}
	}
}

// cleanupLoop runs cleanup every 30 seconds until Stop is called.
func (tm *TaskManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tm.cleanup()
		case <-tm.stopCh:
			return
		}
	}
}

// BuildEnvelopeFromPolicy builds a TaskEnvelope from the agent's resolved
// RBAC permissions and policy config. This resolves wildcards to explicit
// literal arrays at task creation time — tokens never contain wildcards.
func BuildEnvelopeFromPolicy(agentName string, resolved *policy.ResolvedConfig) TaskEnvelope {
	env := TaskEnvelope{}

	perms, hasPerms := resolved.AgentPerms[agentName]

	if !hasPerms || perms.LegacyMode {
		// Legacy mode: include all targets, all roles, all services, all remotes.
		for name := range resolved.Raw.Targets {
			env.Targets = append(env.Targets, name)
		}
		for name := range resolved.Raw.Roles {
			env.Roles = append(env.Roles, name)
		}
		// Legacy agents get all services and remotes.
		env.Services = []string{"*"}
		env.Remotes = []string{"*"}
		env.Methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

		sort.Strings(env.Targets)
		sort.Strings(env.Roles)
		return env
	}

	// RBAC mode: resolve explicit lists from permissions.

	// Targets: check each defined target.
	roleSet := make(map[string]bool)
	for targetName := range resolved.Raw.Targets {
		if perms.CanAccessTarget(targetName) {
			env.Targets = append(env.Targets, targetName)
			// Collect roles the agent can use on this target.
			for _, r := range perms.GetTargetRoles(targetName) {
				roleSet[r] = true
			}
		}
	}
	for r := range roleSet {
		env.Roles = append(env.Roles, r)
	}

	// Services: check each configured service.
	methodSet := make(map[string]bool)
	for svcName, svcAccess := range perms.ServiceAccess {
		if svcName == "*" {
			// Wildcard service access — but we still list explicitly.
			// We cannot enumerate all services from policy alone, so
			// include the wildcard marker for services.
			env.Services = append(env.Services, "*")
			if len(svcAccess.Methods) == 0 {
				methodSet["GET"] = true
				methodSet["POST"] = true
				methodSet["PUT"] = true
				methodSet["PATCH"] = true
				methodSet["DELETE"] = true
				methodSet["HEAD"] = true
				methodSet["OPTIONS"] = true
			} else {
				for _, m := range svcAccess.Methods {
					methodSet[m] = true
				}
			}
			continue
		}
		env.Services = append(env.Services, svcName)
		if len(svcAccess.Methods) == 0 {
			methodSet["GET"] = true
			methodSet["POST"] = true
			methodSet["PUT"] = true
			methodSet["PATCH"] = true
			methodSet["DELETE"] = true
			methodSet["HEAD"] = true
			methodSet["OPTIONS"] = true
		} else {
			for _, m := range svcAccess.Methods {
				methodSet[m] = true
			}
		}
	}
	for m := range methodSet {
		env.Methods = append(env.Methods, m)
	}

	// Remotes: check each configured remote.
	for remoteName := range perms.RemoteAccess {
		env.Remotes = append(env.Remotes, remoteName)
	}

	// Sort for deterministic output.
	sort.Strings(env.Targets)
	sort.Strings(env.Roles)
	sort.Strings(env.Services)
	sort.Strings(env.Remotes)
	sort.Strings(env.Methods)

	return env
}

// DefaultMaxChildDepth is the maximum delegation chain depth.
const DefaultMaxChildDepth = 5

// CreateChildTaskParams holds parameters for creating a child task.
type CreateChildTaskParams struct {
	ParentID    string
	AgentName   string        // must match parent's agent
	Description string
	TTL         time.Duration
	Envelope    *TaskEnvelope // if nil, inherit parent's; if set, must be subset
	CanDelegate bool
}

// IsSubsetOf checks if this envelope is a subset of parent.
// Delegates to token.Envelope.IsSubsetOf for the actual comparison.
func (e *TaskEnvelope) IsSubsetOf(parent *TaskEnvelope) bool {
	te := token.Envelope{
		Targets: e.Targets, Roles: e.Roles, Services: e.Services,
		Remotes: e.Remotes, Methods: e.Methods,
	}
	pe := token.Envelope{
		Targets: parent.Targets, Roles: parent.Roles, Services: parent.Services,
		Remotes: parent.Remotes, Methods: parent.Methods,
	}
	return te.IsSubsetOf(&pe)
}

// CreateChildTask creates a delegated child task under an existing parent task.
// The child inherits the parent's agent, has attenuated (or inherited) envelope,
// and its TTL cannot exceed the parent's remaining lifetime.
func (tm *TaskManager) CreateChildTask(params CreateChildTaskParams) (*Task, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()

	// Lookup parent.
	parent, ok := tm.tasks[params.ParentID]
	if !ok {
		return nil, fmt.Errorf("parent task not found: %s", params.ParentID)
	}

	// Check parent not expired.
	if now.After(parent.ExpiresAt) {
		return nil, fmt.Errorf("parent task has expired: %s", params.ParentID)
	}

	// Agent must match.
	if parent.AgentName != params.AgentName {
		return nil, fmt.Errorf("agent name mismatch: parent is %q, requested %q", parent.AgentName, params.AgentName)
	}

	// Parent must permit delegation.
	if !parent.CanDelegate {
		return nil, fmt.Errorf("parent task does not permit delegation")
	}

	// Check depth limit.
	if parent.Depth+1 > DefaultMaxChildDepth {
		return nil, fmt.Errorf("maximum delegation depth exceeded (max %d)", DefaultMaxChildDepth)
	}

	// Check child TTL does not exceed parent's remaining TTL.
	childExpiry := now.Add(params.TTL)
	if childExpiry.After(parent.ExpiresAt) {
		return nil, fmt.Errorf("child TTL exceeds parent's remaining TTL")
	}

	// Resolve envelope.
	var envelope TaskEnvelope
	if params.Envelope != nil {
		if !params.Envelope.IsSubsetOf(&parent.Envelope) {
			return nil, fmt.Errorf("child envelope exceeds parent envelope")
		}
		envelope = *params.Envelope
	} else {
		envelope = parent.Envelope
	}

	// Generate ID and build lineage.
	id := token.NewULID()

	lineage := make([]string, len(parent.Lineage)+1)
	copy(lineage, parent.Lineage)
	lineage[len(parent.Lineage)] = id

	child := &Task{
		ID:          id,
		RootID:      parent.RootID,
		ParentID:    parent.ID,
		AgentName:   params.AgentName,
		Description: params.Description,
		Depth:       parent.Depth + 1,
		Lineage:     lineage,
		InitiatedBy: parent.InitiatedBy,
		CreatedAt:   now,
		ExpiresAt:   childExpiry,
		Envelope:    envelope,
		CanDelegate: params.CanDelegate,
	}

	// Store.
	tm.tasks[id] = child
	if tm.byAgent[params.AgentName] == nil {
		tm.byAgent[params.AgentName] = make(map[string]bool)
	}
	tm.byAgent[params.AgentName][id] = true

	return child, nil
}

