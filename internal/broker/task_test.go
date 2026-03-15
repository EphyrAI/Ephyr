package broker

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EphyrAI/Ephyr/internal/policy"
	"github.com/EphyrAI/Ephyr/internal/token"
)

func TestCreateRootTask(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		Description: "test task",
		TTL:         5 * time.Minute,
		InitiatedBy: "ephyr:local:uid:1000",
		Envelope: TaskEnvelope{
			Targets:  []string{"dockerhost"},
			Roles:    []string{"read"},
			Services: []string{"grafana"},
		},
	})

	if task == nil {
		t.Fatal("expected non-nil task")
	}

	// ID should be a valid 26-char ULID (Crockford Base32).
	if !token.ValidateULID(task.ID) {
		t.Errorf("invalid ULID: %s", task.ID)
	}

	// Root task: RootID == ID, ParentID empty, Depth 0, Lineage [self].
	if task.RootID != task.ID {
		t.Errorf("root task RootID should equal ID: %s != %s", task.RootID, task.ID)
	}
	if task.ParentID != "" {
		t.Errorf("root task ParentID should be empty, got %q", task.ParentID)
	}
	if task.Depth != 0 {
		t.Errorf("root task depth should be 0, got %d", task.Depth)
	}
	if len(task.Lineage) != 1 || task.Lineage[0] != task.ID {
		t.Errorf("root task lineage should be [self], got %v", task.Lineage)
	}
	if task.AgentName != "agent-1" {
		t.Errorf("expected agent-1, got %s", task.AgentName)
	}
	if task.Description != "test task" {
		t.Errorf("expected 'test task', got %s", task.Description)
	}
	if task.InitiatedBy != "ephyr:local:uid:1000" {
		t.Errorf("expected initiator, got %s", task.InitiatedBy)
	}
	if task.ExpiresAt.Before(task.CreatedAt) {
		t.Error("ExpiresAt should be after CreatedAt")
	}
}

func TestGetTaskByID(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{Targets: []string{"host1"}},
	})

	got := tm.GetTask(task.ID)
	if got == nil {
		t.Fatal("expected to find task by ID")
	}
	if got.ID != task.ID {
		t.Errorf("got wrong task: %s != %s", got.ID, task.ID)
	}
}

func TestGetTaskUnknownID(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	got := tm.GetTask("nonexistent-id")
	if got != nil {
		t.Error("expected nil for unknown ID")
	}
}

func TestGetTaskExpired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       1 * time.Millisecond,
		Envelope:  TaskEnvelope{},
	})

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	got := tm.GetTask(task.ID)
	if got != nil {
		t.Error("expected nil for expired task")
	}
}

func TestListAllTasks(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-2", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	all := tm.ListTasks("")
	if len(all) != 3 {
		t.Errorf("expected 3 tasks, got %d", len(all))
	}
}

func TestListTasksByAgent(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-2", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	agent1Tasks := tm.ListTasksByAgent("agent-1")
	if len(agent1Tasks) != 2 {
		t.Errorf("expected 2 tasks for agent-1, got %d", len(agent1Tasks))
	}
	for _, task := range agent1Tasks {
		if task.AgentName != "agent-1" {
			t.Errorf("expected agent-1, got %s", task.AgentName)
		}
	}

	agent2Tasks := tm.ListTasksByAgent("agent-2")
	if len(agent2Tasks) != 1 {
		t.Errorf("expected 1 task for agent-2, got %d", len(agent2Tasks))
	}
}

func TestListTasksExcludesExpired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 1 * time.Millisecond, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	time.Sleep(5 * time.Millisecond)

	tasks := tm.ListTasks("")
	if len(tasks) != 1 {
		t.Errorf("expected 1 active task, got %d", len(tasks))
	}
}

func TestRevokeTask(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{},
	})

	revoked := tm.RevokeTask(task.ID)
	if revoked == nil {
		t.Fatal("expected revoked task to be returned")
	}
	if revoked.ID != task.ID {
		t.Errorf("revoked wrong task: %s != %s", revoked.ID, task.ID)
	}
}

func TestRevokedTaskNotReturned(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{},
	})

	tm.RevokeTask(task.ID)

	got := tm.GetTask(task.ID)
	if got != nil {
		t.Error("expected nil after revocation")
	}

	// Also not in list.
	tasks := tm.ListTasks("")
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks after revocation, got %d", len(tasks))
	}
}

func TestRevokeNonexistent(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	revoked := tm.RevokeTask("does-not-exist")
	if revoked != nil {
		t.Error("expected nil for nonexistent revocation")
	}
}

func TestCleanupRemovesExpired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 1 * time.Millisecond, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-2", TTL: 1 * time.Millisecond, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "agent-1", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	time.Sleep(5 * time.Millisecond)
	tm.cleanup()

	// Only the non-expired task should remain.
	tm.mu.RLock()
	count := len(tm.tasks)
	tm.mu.RUnlock()
	if count != 1 {
		t.Errorf("expected 1 task after cleanup, got %d", count)
	}
}

func TestTaskCount(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	if tm.TaskCount() != 0 {
		t.Error("expected 0 tasks initially")
	}

	tm.CreateTask(CreateTaskParams{AgentName: "a", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	tm.CreateTask(CreateTaskParams{AgentName: "b", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	if tm.TaskCount() != 2 {
		t.Errorf("expected 2 tasks, got %d", tm.TaskCount())
	}

	// Add an expired one.
	tm.CreateTask(CreateTaskParams{AgentName: "c", TTL: 1 * time.Millisecond, Envelope: TaskEnvelope{}})
	time.Sleep(5 * time.Millisecond)

	if tm.TaskCount() != 2 {
		t.Errorf("expected 2 active tasks (1 expired), got %d", tm.TaskCount())
	}
}

func TestIsTaskActive(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{AgentName: "a", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	if !tm.IsTaskActive(task.ID) {
		t.Error("expected task to be active")
	}
	if tm.IsTaskActive("nonexistent") {
		t.Error("expected nonexistent task to be inactive")
	}
}

func TestConcurrentCreateGetList(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	var wg sync.WaitGroup
	const numGoroutines = 50

	// Concurrent creates.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.CreateTask(CreateTaskParams{
				AgentName: "agent-concurrent",
				TTL:       5 * time.Minute,
				Envelope:  TaskEnvelope{},
			})
		}()
	}

	// Concurrent reads while creates are happening.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tm.ListTasks("")
			tm.TaskCount()
		}()
	}

	wg.Wait()

	count := tm.TaskCount()
	if count != numGoroutines {
		t.Errorf("expected %d tasks, got %d", numGoroutines, count)
	}
}

func TestULIDUniqueness(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		task := tm.CreateTask(CreateTaskParams{
			AgentName: "agent",
			TTL:       5 * time.Minute,
			Envelope:  TaskEnvelope{},
		})
		if ids[task.ID] {
			t.Fatalf("duplicate ULID at iteration %d: %s", i, task.ID)
		}
		ids[task.ID] = true
	}
}

func TestTaskEnvelopePreserved(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	env := TaskEnvelope{
		Targets:  []string{"host-a", "host-b"},
		Roles:    []string{"read", "operator"},
		Services: []string{"grafana", "portainer"},
		Remotes:  []string{"demo-tools"},
		Methods:  []string{"GET", "POST"},
	}

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  env,
	})

	got := tm.GetTask(task.ID)
	if len(got.Envelope.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(got.Envelope.Targets))
	}
	if len(got.Envelope.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(got.Envelope.Roles))
	}
	if len(got.Envelope.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(got.Envelope.Services))
	}
	if len(got.Envelope.Remotes) != 1 {
		t.Errorf("expected 1 remote, got %d", len(got.Envelope.Remotes))
	}
	if len(got.Envelope.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(got.Envelope.Methods))
	}
}

func TestListTasksSortedByCreation(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	t1 := tm.CreateTask(CreateTaskParams{AgentName: "a", Description: "first", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	time.Sleep(1 * time.Millisecond) // ensure different timestamps
	t2 := tm.CreateTask(CreateTaskParams{AgentName: "a", Description: "second", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	time.Sleep(1 * time.Millisecond)
	t3 := tm.CreateTask(CreateTaskParams{AgentName: "b", Description: "third", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	tasks := tm.ListTasks("")
	if len(tasks) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(tasks))
	}
	if tasks[0].ID != t1.ID || tasks[1].ID != t2.ID || tasks[2].ID != t3.ID {
		t.Error("tasks not sorted by creation time")
	}
}

// --- BuildEnvelopeFromPolicy tests ---

func TestBuildEnvelopeFromPolicyWithRBAC(t *testing.T) {
	trueVal := true
	resolved := &policy.ResolvedConfig{
		Raw: &policy.Config{
			Targets: map[string]policy.TargetPolicy{
				"dockerhost":    {Host: "192.168.100.100", AllowedRoles: []string{"read", "operator", "admin"}},
				"hugoblog":      {Host: "192.168.100.63", AllowedRoles: []string{"read", "operator"}},
				"mandrake-rack": {Host: "192.168.30.55", AllowedRoles: []string{"read", "operator"}},
			},
			Roles: map[string]policy.RoleDefinition{
				"read":     {Principal: "agent-read"},
				"operator": {Principal: "agent-op"},
				"admin":    {Principal: "agent-admin"},
			},
		},
		AgentPerms: map[string]*policy.ResolvedAgentPerms{
			"test-agent": {
				SSHAccess: map[string]*policy.AgentTargetAccess{
					"dockerhost": {Roles: []string{"read", "operator"}, AutoApprove: &trueVal},
					"hugoblog":   {Roles: []string{"read"}, AutoApprove: &trueVal},
				},
				ServiceAccess: map[string]*policy.ServiceAccess{
					"grafana":   {Methods: []string{"GET"}},
					"portainer": {Methods: []string{"GET", "POST"}},
				},
				RemoteAccess: map[string]*policy.RemoteAccess{
					"demo-tools": {Tools: []string{"roll_dice"}},
				},
				LegacyMode: false,
			},
		},
	}

	env := BuildEnvelopeFromPolicy("test-agent", resolved)

	// Should have dockerhost and hugoblog but NOT mandrake-rack.
	if len(env.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d: %v", len(env.Targets), env.Targets)
	}
	foundDocker, foundHugo := false, false
	for _, tgt := range env.Targets {
		if tgt == "dockerhost" {
			foundDocker = true
		}
		if tgt == "hugoblog" {
			foundHugo = true
		}
	}
	if !foundDocker || !foundHugo {
		t.Errorf("expected dockerhost and hugoblog in targets: %v", env.Targets)
	}

	// Roles: read and operator (from dockerhost + hugoblog).
	if len(env.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d: %v", len(env.Roles), env.Roles)
	}

	// Services: grafana and portainer.
	if len(env.Services) != 2 {
		t.Errorf("expected 2 services, got %d: %v", len(env.Services), env.Services)
	}

	// Methods: GET and POST.
	if len(env.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d: %v", len(env.Methods), env.Methods)
	}

	// Remotes: demo-tools.
	if len(env.Remotes) != 1 || env.Remotes[0] != "demo-tools" {
		t.Errorf("expected [demo-tools], got %v", env.Remotes)
	}
}

func TestBuildEnvelopeFromPolicyLegacyMode(t *testing.T) {
	resolved := &policy.ResolvedConfig{
		Raw: &policy.Config{
			Targets: map[string]policy.TargetPolicy{
				"dockerhost":    {Host: "192.168.100.100", AllowedRoles: []string{"read", "operator"}},
				"mandrake-rack": {Host: "192.168.30.55", AllowedRoles: []string{"read"}},
			},
			Roles: map[string]policy.RoleDefinition{
				"read":     {Principal: "agent-read"},
				"operator": {Principal: "agent-op"},
			},
		},
		AgentPerms: map[string]*policy.ResolvedAgentPerms{
			"legacy-agent": {
				LegacyMode: true,
			},
		},
	}

	env := BuildEnvelopeFromPolicy("legacy-agent", resolved)

	// Legacy mode: all targets and roles.
	if len(env.Targets) != 2 {
		t.Errorf("expected 2 targets (all), got %d: %v", len(env.Targets), env.Targets)
	}
	if len(env.Roles) != 2 {
		t.Errorf("expected 2 roles (all), got %d: %v", len(env.Roles), env.Roles)
	}
	// Wildcard services.
	if len(env.Services) != 1 || env.Services[0] != "*" {
		t.Errorf("expected [*] services, got %v", env.Services)
	}
	// All HTTP methods.
	if len(env.Methods) != 7 {
		t.Errorf("expected 7 methods, got %d: %v", len(env.Methods), env.Methods)
	}
}

func TestBuildEnvelopeFromPolicyUnknownAgent(t *testing.T) {
	resolved := &policy.ResolvedConfig{
		Raw: &policy.Config{
			Targets: map[string]policy.TargetPolicy{
				"host1": {Host: "1.2.3.4", AllowedRoles: []string{"read"}},
			},
			Roles: map[string]policy.RoleDefinition{
				"read": {Principal: "agent-read"},
			},
		},
		AgentPerms: map[string]*policy.ResolvedAgentPerms{},
	}

	// Agent not in perms map => treated as legacy (full access).
	env := BuildEnvelopeFromPolicy("unknown-agent", resolved)

	if len(env.Targets) != 1 {
		t.Errorf("expected 1 target (legacy fallback), got %d", len(env.Targets))
	}
}

func TestBuildEnvelopeFromPolicyWildcardSSH(t *testing.T) {
	resolved := &policy.ResolvedConfig{
		Raw: &policy.Config{
			Targets: map[string]policy.TargetPolicy{
				"host1": {Host: "1.1.1.1", AllowedRoles: []string{"read", "operator"}},
				"host2": {Host: "2.2.2.2", AllowedRoles: []string{"read"}},
			},
			Roles: map[string]policy.RoleDefinition{
				"read":     {Principal: "agent-read"},
				"operator": {Principal: "agent-op"},
			},
		},
		AgentPerms: map[string]*policy.ResolvedAgentPerms{
			"wildcard-agent": {
				SSHAccess: map[string]*policy.AgentTargetAccess{
					"*": {Roles: []string{"read"}},
				},
				ServiceAccess: map[string]*policy.ServiceAccess{},
				RemoteAccess:  map[string]*policy.RemoteAccess{},
				LegacyMode:    false,
			},
		},
	}

	env := BuildEnvelopeFromPolicy("wildcard-agent", resolved)

	// Wildcard SSH: should match both hosts.
	if len(env.Targets) != 2 {
		t.Errorf("expected 2 targets with wildcard, got %d: %v", len(env.Targets), env.Targets)
	}
	// Roles should be just "read" (from wildcard, intersected with each target).
	if len(env.Roles) != 1 || env.Roles[0] != "read" {
		t.Errorf("expected [read], got %v", env.Roles)
	}
}

// --- CreateChildTask delegation tests ---

// helper to create a delegating parent task with standard envelope.
func createDelegatingParent(tm *TaskManager) *Task {
	return tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		Description: "parent task",
		TTL:         60 * time.Minute,
		InitiatedBy: "ephyr:local:uid:1000",
		Envelope: TaskEnvelope{
			Targets:  []string{"dockerhost", "hugoblog"},
			Roles:    []string{"read", "operator"},
			Services: []string{"grafana", "portainer"},
			Remotes:  []string{"demo-tools"},
			Methods:  []string{"GET", "POST"},
		},
		CanDelegate: true,
	})
}

func TestCreateChildTask_Basic(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child task",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify child properties.
	if !token.ValidateULID(child.ID) {
		t.Errorf("invalid child ULID: %s", child.ID)
	}
	if child.Depth != 1 {
		t.Errorf("expected depth 1, got %d", child.Depth)
	}
	if child.RootID != parent.ID {
		t.Errorf("expected RootID %s, got %s", parent.ID, child.RootID)
	}
	if child.ParentID != parent.ID {
		t.Errorf("expected ParentID %s, got %s", parent.ID, child.ParentID)
	}
	if len(child.Lineage) != 2 {
		t.Fatalf("expected lineage length 2, got %d", len(child.Lineage))
	}
	if child.Lineage[0] != parent.ID {
		t.Errorf("lineage[0] should be parent ID %s, got %s", parent.ID, child.Lineage[0])
	}
	if child.Lineage[1] != child.ID {
		t.Errorf("lineage[1] should be child ID %s, got %s", child.ID, child.Lineage[1])
	}
	if child.AgentName != "agent-1" {
		t.Errorf("expected agent-1, got %s", child.AgentName)
	}
	if child.CanDelegate != false {
		t.Error("expected CanDelegate false")
	}

	// Child should be retrievable.
	got := tm.GetTask(child.ID)
	if got == nil {
		t.Fatal("child task not found via GetTask")
	}
}

func TestCreateChildTask_LineageChain(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child",
		TTL:         5 * time.Minute,
		CanDelegate: true,
	})
	if err != nil {
		t.Fatalf("unexpected error creating child: %v", err)
	}

	grandchild, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    child.ID,
		AgentName:   "agent-1",
		Description: "grandchild",
		TTL:         3 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating grandchild: %v", err)
	}

	// Verify lineage chain.
	if grandchild.Depth != 2 {
		t.Errorf("expected depth 2, got %d", grandchild.Depth)
	}
	if grandchild.RootID != parent.ID {
		t.Errorf("expected RootID %s, got %s", parent.ID, grandchild.RootID)
	}
	if grandchild.ParentID != child.ID {
		t.Errorf("expected ParentID %s, got %s", child.ID, grandchild.ParentID)
	}
	expectedLineage := []string{parent.ID, child.ID, grandchild.ID}
	if len(grandchild.Lineage) != 3 {
		t.Fatalf("expected lineage length 3, got %d: %v", len(grandchild.Lineage), grandchild.Lineage)
	}
	for i, id := range expectedLineage {
		if grandchild.Lineage[i] != id {
			t.Errorf("lineage[%d] = %s, want %s", i, grandchild.Lineage[i], id)
		}
	}
}

func TestCreateChildTask_DepthLimit(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Create a chain up to max depth.
	parent := createDelegatingParent(tm)
	current := parent

	// DefaultMaxChildDepth is 5, so we can create children at depths 1..5.
	// Each child uses a decreasing TTL to stay within its parent's remaining TTL.
	for i := 1; i <= DefaultMaxChildDepth; i++ {
		childTTL := time.Duration(DefaultMaxChildDepth+1-i) * time.Minute
		child, err := tm.CreateChildTask(CreateChildTaskParams{
			ParentID:    current.ID,
			AgentName:   "agent-1",
			Description: "chain link",
			TTL:         childTTL,
			CanDelegate: true,
		})
		if err != nil {
			t.Fatalf("unexpected error at depth %d: %v", i, err)
		}
		if child.Depth != i {
			t.Errorf("expected depth %d, got %d", i, child.Depth)
		}
		current = child
	}

	// The next one (depth 6) should fail.
	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    current.ID,
		AgentName:   "agent-1",
		Description: "one too many",
		TTL:         1 * time.Minute,
		CanDelegate: false,
	})
	if err == nil {
		t.Fatal("expected error for exceeding max depth")
	}
	if !strings.Contains(err.Error(), "maximum delegation depth") {
		t.Errorf("expected 'maximum delegation depth' error, got: %v", err)
	}
}

func TestCreateChildTask_TTLConstraint(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		TTL:         2 * time.Minute,
		Envelope:    TaskEnvelope{Targets: []string{"host1"}},
		CanDelegate: true,
	})

	// Child TTL exceeds parent remaining TTL.
	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for excessive child TTL")
	}
	if !strings.Contains(err.Error(), "child TTL exceeds parent's remaining TTL") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Child TTL within parent remaining TTL should succeed.
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if child.ExpiresAt.After(parent.ExpiresAt) {
		t.Error("child expiry should not exceed parent expiry")
	}
}

func TestCreateChildTask_EnvelopeAttenuation(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	// Subset envelope: fewer targets, fewer roles.
	subset := &TaskEnvelope{
		Targets:  []string{"dockerhost"},
		Roles:    []string{"read"},
		Services: []string{"grafana"},
		Remotes:  []string{"demo-tools"},
		Methods:  []string{"GET"},
	}

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  subset,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify child has the attenuated envelope.
	if len(child.Envelope.Targets) != 1 || child.Envelope.Targets[0] != "dockerhost" {
		t.Errorf("expected [dockerhost], got %v", child.Envelope.Targets)
	}
	if len(child.Envelope.Roles) != 1 || child.Envelope.Roles[0] != "read" {
		t.Errorf("expected [read], got %v", child.Envelope.Roles)
	}
}

func TestCreateChildTask_EnvelopeViolation(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	// Superset envelope: includes target not in parent.
	superset := &TaskEnvelope{
		Targets:  []string{"dockerhost", "hugoblog", "mandrake-rack"},
		Roles:    []string{"read"},
		Services: []string{"grafana"},
		Methods:  []string{"GET"},
	}

	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  superset,
	})
	if err == nil {
		t.Fatal("expected error for superset envelope")
	}
	if !strings.Contains(err.Error(), "child envelope exceeds parent envelope") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateChildTask_EnvelopeInheritance(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	// nil envelope should inherit parent's.
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify inherited envelope matches parent's.
	if len(child.Envelope.Targets) != len(parent.Envelope.Targets) {
		t.Errorf("targets count mismatch: child %d, parent %d",
			len(child.Envelope.Targets), len(parent.Envelope.Targets))
	}
	for i, tgt := range parent.Envelope.Targets {
		if child.Envelope.Targets[i] != tgt {
			t.Errorf("target[%d]: child %s != parent %s", i, child.Envelope.Targets[i], tgt)
		}
	}
	if len(child.Envelope.Roles) != len(parent.Envelope.Roles) {
		t.Errorf("roles count mismatch: child %d, parent %d",
			len(child.Envelope.Roles), len(parent.Envelope.Roles))
	}
	if len(child.Envelope.Services) != len(parent.Envelope.Services) {
		t.Errorf("services count mismatch: child %d, parent %d",
			len(child.Envelope.Services), len(parent.Envelope.Services))
	}
	if len(child.Envelope.Methods) != len(parent.Envelope.Methods) {
		t.Errorf("methods count mismatch: child %d, parent %d",
			len(child.Envelope.Methods), len(parent.Envelope.Methods))
	}
}

func TestCreateChildTask_CanDelegateRequired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Parent with CanDelegate: false.
	parent := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		TTL:         10 * time.Minute,
		Envelope:    TaskEnvelope{Targets: []string{"host1"}},
		CanDelegate: false,
	})

	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error when parent does not permit delegation")
	}
	if !strings.Contains(err.Error(), "parent task does not permit delegation") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateChildTask_DifferentAgentRejected(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-2", // different from parent's "agent-1"
		TTL:       5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for different agent")
	}
	if !strings.Contains(err.Error(), "agent name mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateChildTask_ParentNotFound(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  "01BOGUS0000000000000000000",
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent parent")
	}
	if !strings.Contains(err.Error(), "parent task not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateChildTask_ParentExpired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		TTL:         1 * time.Millisecond,
		Envelope:    TaskEnvelope{Targets: []string{"host1"}},
		CanDelegate: true,
	})

	// Wait for parent to expire.
	time.Sleep(5 * time.Millisecond)

	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:  parent.ID,
		AgentName: "agent-1",
		TTL:       1 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected error for expired parent")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCreateChildTask_ConcurrentCreation(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	const numGoroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tm.CreateChildTask(CreateChildTaskParams{
				ParentID:  parent.ID,
				AgentName: "agent-1",
				TTL:       5 * time.Minute,
			})
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("unexpected error in concurrent creation: %v", err)
	}

	// Should have parent + 50 children = 51 total.
	count := tm.TaskCount()
	if count != numGoroutines+1 {
		t.Errorf("expected %d tasks, got %d", numGoroutines+1, count)
	}

	// Verify all child IDs are unique.
	tasks := tm.ListTasks("agent-1")
	ids := make(map[string]bool)
	for _, task := range tasks {
		if ids[task.ID] {
			t.Errorf("duplicate task ID: %s", task.ID)
		}
		ids[task.ID] = true
	}
}

func TestCreateChildTask_LineageCopySafety(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child",
		TTL:         5 * time.Minute,
		CanDelegate: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Save copies of lineages before mutation.
	parentLineageBefore := make([]string, len(parent.Lineage))
	copy(parentLineageBefore, parent.Lineage)
	childLineageBefore := make([]string, len(child.Lineage))
	copy(childLineageBefore, child.Lineage)

	// Create a second child from the same parent — this should not affect
	// the first child's lineage.
	child2, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child2",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating child2: %v", err)
	}

	// Verify parent lineage unchanged.
	if len(parent.Lineage) != len(parentLineageBefore) {
		t.Fatalf("parent lineage length changed: %d -> %d", len(parentLineageBefore), len(parent.Lineage))
	}
	for i, id := range parentLineageBefore {
		if parent.Lineage[i] != id {
			t.Errorf("parent lineage[%d] changed: %s -> %s", i, id, parent.Lineage[i])
		}
	}

	// Verify first child's lineage unchanged.
	if len(child.Lineage) != len(childLineageBefore) {
		t.Fatalf("child lineage length changed: %d -> %d", len(childLineageBefore), len(child.Lineage))
	}
	for i, id := range childLineageBefore {
		if child.Lineage[i] != id {
			t.Errorf("child lineage[%d] changed: %s -> %s", i, id, child.Lineage[i])
		}
	}

	// Verify child2 has its own lineage.
	if len(child2.Lineage) != 2 {
		t.Fatalf("expected child2 lineage length 2, got %d", len(child2.Lineage))
	}
	if child2.Lineage[0] != parent.ID || child2.Lineage[1] != child2.ID {
		t.Errorf("unexpected child2 lineage: %v", child2.Lineage)
	}

	// Mutate child's lineage and verify parent is unaffected (no shared backing array).
	child.Lineage[0] = "MUTATED"
	if parent.Lineage[0] == "MUTATED" {
		t.Error("child lineage mutation affected parent — backing array is shared!")
	}
}

// --- GetChildren / GetTaskTree / CountDelegations / ListAllTasks tests ---

func TestGetChildren_Basic(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child1, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child-1",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating child1: %v", err)
	}

	time.Sleep(1 * time.Millisecond) // ensure different timestamps

	child2, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child-2",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating child2: %v", err)
	}

	children := tm.GetChildren(parent.ID)
	if len(children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(children))
	}

	// Should be sorted by CreatedAt ascending.
	if children[0].ID != child1.ID {
		t.Errorf("expected first child to be %s, got %s", child1.ID, children[0].ID)
	}
	if children[1].ID != child2.ID {
		t.Errorf("expected second child to be %s, got %s", child2.ID, children[1].ID)
	}
}

func TestGetChildren_NoChildren(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	root := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{Targets: []string{"host1"}},
	})

	children := tm.GetChildren(root.ID)
	if children == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(children) != 0 {
		t.Errorf("expected 0 children, got %d", len(children))
	}
}

func TestGetTaskTree_MultiLevel(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	root := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    root.ID,
		AgentName:   "agent-1",
		Description: "child",
		TTL:         30 * time.Minute,
		CanDelegate: true,
	})
	if err != nil {
		t.Fatalf("unexpected error creating child: %v", err)
	}

	grandchild, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    child.ID,
		AgentName:   "agent-1",
		Description: "grandchild",
		TTL:         10 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error creating grandchild: %v", err)
	}

	tree := tm.GetTaskTree(root.ID)
	if len(tree) != 3 {
		t.Fatalf("expected 3 tasks in tree, got %d", len(tree))
	}

	// Should be sorted by depth ascending.
	if tree[0].ID != root.ID {
		t.Errorf("expected tree[0] to be root %s, got %s", root.ID, tree[0].ID)
	}
	if tree[0].Depth != 0 {
		t.Errorf("expected tree[0] depth 0, got %d", tree[0].Depth)
	}
	if tree[1].ID != child.ID {
		t.Errorf("expected tree[1] to be child %s, got %s", child.ID, tree[1].ID)
	}
	if tree[1].Depth != 1 {
		t.Errorf("expected tree[1] depth 1, got %d", tree[1].Depth)
	}
	if tree[2].ID != grandchild.ID {
		t.Errorf("expected tree[2] to be grandchild %s, got %s", grandchild.ID, tree[2].ID)
	}
	if tree[2].Depth != 2 {
		t.Errorf("expected tree[2] depth 2, got %d", tree[2].Depth)
	}
}

func TestGetTaskTree_ExcludesOtherRoots(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Tree 1: root1 -> child1
	root1 := createDelegatingParent(tm)
	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    root1.ID,
		AgentName:   "agent-1",
		Description: "tree1-child",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tree 2: root2 -> child2
	root2 := createDelegatingParent(tm)
	_, err = tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    root2.ID,
		AgentName:   "agent-1",
		Description: "tree2-child",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GetTaskTree for root1 should only return root1's tree.
	tree1 := tm.GetTaskTree(root1.ID)
	if len(tree1) != 2 {
		t.Fatalf("expected 2 tasks in tree1, got %d", len(tree1))
	}
	for _, task := range tree1 {
		if task.RootID != root1.ID {
			t.Errorf("tree1 contains task with RootID %s, expected %s", task.RootID, root1.ID)
		}
	}

	// GetTaskTree for root2 should only return root2's tree.
	tree2 := tm.GetTaskTree(root2.ID)
	if len(tree2) != 2 {
		t.Fatalf("expected 2 tasks in tree2, got %d", len(tree2))
	}
	for _, task := range tree2 {
		if task.RootID != root2.ID {
			t.Errorf("tree2 contains task with RootID %s, expected %s", task.RootID, root2.ID)
		}
	}
}

func TestCountDelegations(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// 2 root tasks (depth 0).
	root1 := createDelegatingParent(tm)
	root2 := createDelegatingParent(tm)

	// 3 delegated children (depth > 0).
	for i := 0; i < 2; i++ {
		_, err := tm.CreateChildTask(CreateChildTaskParams{
			ParentID:    root1.ID,
			AgentName:   "agent-1",
			Description: "delegation",
			TTL:         5 * time.Minute,
			CanDelegate: false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	_, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    root2.ID,
		AgentName:   "agent-1",
		Description: "delegation",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := tm.CountDelegations()
	if count != 3 {
		t.Errorf("expected 3 delegations, got %d", count)
	}
}

func TestListAllTasks_MultiAgent(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	t1 := tm.CreateTask(CreateTaskParams{AgentName: "agent-1", Description: "first", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	time.Sleep(1 * time.Millisecond)
	t2 := tm.CreateTask(CreateTaskParams{AgentName: "agent-2", Description: "second", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})
	time.Sleep(1 * time.Millisecond)
	t3 := tm.CreateTask(CreateTaskParams{AgentName: "agent-3", Description: "third", TTL: 5 * time.Minute, Envelope: TaskEnvelope{}})

	all := tm.ListAllTasks()
	if len(all) != 3 {
		t.Fatalf("expected 3 tasks, got %d", len(all))
	}

	// ListAllTasks sorts newest first (CreatedAt descending).
	if all[0].ID != t3.ID {
		t.Errorf("expected newest task first (t3 %s), got %s", t3.ID, all[0].ID)
	}
	if all[1].ID != t2.ID {
		t.Errorf("expected second newest (t2 %s), got %s", t2.ID, all[1].ID)
	}
	if all[2].ID != t1.ID {
		t.Errorf("expected oldest last (t1 %s), got %s", t1.ID, all[2].ID)
	}

	// Verify all agents are represented.
	agents := make(map[string]bool)
	for _, task := range all {
		agents[task.AgentName] = true
	}
	if !agents["agent-1"] || !agents["agent-2"] || !agents["agent-3"] {
		t.Errorf("expected all 3 agents represented, got %v", agents)
	}
}

// --- Signature index tests ---

func TestSignatureIndex_RegisterAndLookup(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{Targets: []string{"host1"}},
	})

	digest := "abc123deadbeef"
	task.MacaroonSigDigest = digest
	tm.RegisterSignature(digest, task.ID)

	got := tm.LookupBySignature(digest)
	if got == nil {
		t.Fatal("expected to find task by signature")
	}
	if got.ID != task.ID {
		t.Errorf("expected task %s, got %s", task.ID, got.ID)
	}
}

func TestSignatureIndex_NotFound(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	got := tm.LookupBySignature("nonexistent")
	if got != nil {
		t.Error("expected nil for nonexistent digest")
	}
}

func TestSignatureIndex_Unregister(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{Targets: []string{"host1"}},
	})

	digest := "abc123"
	tm.RegisterSignature(digest, task.ID)
	tm.UnregisterSignature(digest)

	if tm.LookupBySignature(digest) != nil {
		t.Error("expected nil after unregister")
	}
}

func TestSignatureIndex_RevokeCleansSig(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName: "agent-1",
		TTL:       5 * time.Minute,
		Envelope:  TaskEnvelope{Targets: []string{"host1"}},
	})

	digest := "revoke-test-sig"
	task.MacaroonSigDigest = digest
	tm.RegisterSignature(digest, task.ID)

	tm.RevokeTask(task.ID)

	if tm.LookupBySignature(digest) != nil {
		t.Error("expected nil after revoke")
	}
}

func TestSignatureIndex_ConcurrentAccess(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Create multiple tasks and register signatures concurrently
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			task := tm.CreateTask(CreateTaskParams{
				AgentName: "agent-1",
				TTL:       5 * time.Minute,
				Envelope:  TaskEnvelope{Targets: []string{"host1"}},
			})
			digest := fmt.Sprintf("sig-%d", i)
			task.MacaroonSigDigest = digest
			tm.RegisterSignature(digest, task.ID)

			// Also lookup
			tm.LookupBySignature(digest)
		}(i)
	}
	wg.Wait()
}

// --- Ephyr Bind (v0.3.1): holder-bound token tests ---

// testPubKey returns a deterministic 32-byte Ed25519 public key for testing.
func testPubKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return key
}

func TestBindHolderKey_Basic(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "child for binding",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Child should start unbound with a deadline set.
	if child.HolderBound {
		t.Error("expected child to start unbound")
	}
	if child.BindDeadline.IsZero() {
		t.Error("expected bind deadline to be set")
	}

	// Bind a key.
	pubKey := testPubKey(0xAA)
	if err := tm.BindHolderKey(child.ID, pubKey); err != nil {
		t.Fatalf("unexpected error binding key: %v", err)
	}

	// Verify fields.
	got := tm.GetTask(child.ID)
	if got == nil {
		t.Fatal("task not found after binding")
	}
	if !got.HolderBound {
		t.Error("expected HolderBound to be true after binding")
	}
	if len(got.HolderPubKey) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(got.HolderPubKey))
	}
	for i, b := range got.HolderPubKey {
		if b != 0xAA {
			t.Errorf("key byte[%d] = %x, want 0xAA", i, b)
			break
		}
	}
	if !got.BindDeadline.IsZero() {
		t.Error("expected bind deadline to be cleared after binding")
	}
}

func TestBindHolderKey_Idempotent(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "idempotent test",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pubKey := testPubKey(0xBB)

	// Bind first time.
	if err := tm.BindHolderKey(child.ID, pubKey); err != nil {
		t.Fatalf("first bind failed: %v", err)
	}

	// Bind same key again -- should succeed (idempotent).
	if err := tm.BindHolderKey(child.ID, pubKey); err != nil {
		t.Fatalf("idempotent bind failed: %v", err)
	}
}

func TestBindHolderKey_DifferentKeyRejected(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "different key test",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Bind first key.
	if err := tm.BindHolderKey(child.ID, testPubKey(0xCC)); err != nil {
		t.Fatalf("first bind failed: %v", err)
	}

	// Try binding a different key -- should fail.
	err = tm.BindHolderKey(child.ID, testPubKey(0xDD))
	if err == nil {
		t.Fatal("expected error when binding a different key")
	}
	if !strings.Contains(err.Error(), "key already bound") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBindHolderKey_DeadlineExpired(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "deadline test",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually set deadline to the past to simulate expiry.
	tm.mu.Lock()
	tm.tasks[child.ID].BindDeadline = time.Now().Add(-1 * time.Second)
	tm.mu.Unlock()

	err = tm.BindHolderKey(child.ID, testPubKey(0xEE))
	if err == nil {
		t.Fatal("expected error when bind deadline has expired")
	}
	if !strings.Contains(err.Error(), "bind deadline expired") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBindHolderKey_InvalidKeySize(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)
	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "invalid key test",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try binding a key that is not 32 bytes.
	shortKey := make([]byte, 16)
	err = tm.BindHolderKey(child.ID, shortKey)
	if err == nil {
		t.Fatal("expected error for non-32-byte key")
	}
	if !strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("unexpected error message: %v", err)
	}

	longKey := make([]byte, 64)
	err = tm.BindHolderKey(child.ID, longKey)
	if err == nil {
		t.Fatal("expected error for 64-byte key")
	}
}

func TestBindHolderKey_TaskNotFound(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	err := tm.BindHolderKey("nonexistent", testPubKey(0xFF))
	if err == nil {
		t.Fatal("expected error for nonexistent task")
	}
	if !strings.Contains(err.Error(), "task not found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateTask_WithHolderPubKey(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	pubKey := testPubKey(0x42)
	task := tm.CreateTask(CreateTaskParams{
		AgentName:    "agent-1",
		Description:  "bound root task",
		TTL:          5 * time.Minute,
		InitiatedBy:  "ephyr:local:uid:1000",
		Envelope:     TaskEnvelope{Targets: []string{"dockerhost"}},
		HolderPubKey: pubKey,
	})

	// Task created with key should be immediately bound.
	if !task.HolderBound {
		t.Error("expected task to be holder-bound when created with pub key")
	}
	if len(task.HolderPubKey) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(task.HolderPubKey))
	}
	if task.HolderPubKey[0] != 0x42 {
		t.Errorf("expected key byte 0x42, got 0x%02x", task.HolderPubKey[0])
	}
	// BindDeadline should not be set for immediately-bound root tasks.
	if !task.BindDeadline.IsZero() {
		t.Error("expected no bind deadline for immediately-bound task")
	}

	// Verify key is a copy (mutation safety).
	pubKey[0] = 0xFF
	if task.HolderPubKey[0] == 0xFF {
		t.Error("task holds reference to original key slice -- should be a copy")
	}
}

func TestCreateTask_WithoutHolderPubKey(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		Description: "unbound root task",
		TTL:         5 * time.Minute,
		Envelope:    TaskEnvelope{Targets: []string{"dockerhost"}},
	})

	// Root task without holder key should not be bound.
	if task.HolderBound {
		t.Error("expected task to not be holder-bound when created without pub key")
	}
	if task.HolderPubKey != nil {
		t.Error("expected nil HolderPubKey")
	}
}

func TestCreateChildTask_UnboundWithDeadline(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "delegated child",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Child task should start unbound with a bind deadline.
	if child.HolderBound {
		t.Error("expected delegated child to be unbound (HolderBound=false)")
	}
	if child.HolderPubKey != nil {
		t.Error("expected nil HolderPubKey for unbound child")
	}
	if child.BindDeadline.IsZero() {
		t.Error("expected bind deadline to be set for delegated child")
	}

	// The bind deadline should be approximately DefaultBindDeadline from now.
	expectedDeadline := time.Now().Add(DefaultBindDeadline)
	deadlineDiff := child.BindDeadline.Sub(expectedDeadline)
	if deadlineDiff < -2*time.Second || deadlineDiff > 2*time.Second {
		t.Errorf("bind deadline off by too much: expected ~%v, got %v (diff %v)",
			expectedDeadline, child.BindDeadline, deadlineDiff)
	}
}

func TestCleanup_AutoRevokesUnboundPastDeadline(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "unbound child",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually set bind deadline to the past.
	tm.mu.Lock()
	tm.tasks[child.ID].BindDeadline = time.Now().Add(-1 * time.Second)
	tm.mu.Unlock()

	// Run cleanup.
	var expiredIDs []string
	tm.OnExpire = func(task *Task) {
		expiredIDs = append(expiredIDs, task.ID)
	}
	tm.cleanup()

	// The unbound child should have been cleaned up.
	got := tm.GetTask(child.ID)
	if got != nil {
		t.Error("expected unbound child past deadline to be removed by cleanup")
	}

	// Verify OnExpire was called for the child.
	found := false
	for _, id := range expiredIDs {
		if id == child.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OnExpire to be called for unbound child past deadline")
	}

	// Parent should still be alive (not unbound, no deadline issue).
	parentGot := tm.GetTask(parent.ID)
	if parentGot == nil {
		t.Error("expected parent to still be active after cleanup")
	}
}

func TestCleanup_DoesNotRevokeUnboundBeforeDeadline(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "unbound child within deadline",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Deadline is ~30s from now -- should NOT be cleaned up.
	tm.cleanup()

	got := tm.GetTask(child.ID)
	if got == nil {
		t.Error("expected unbound child within deadline to survive cleanup")
	}
}

func TestCleanup_DoesNotRevokeBoundTask(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	parent := createDelegatingParent(tm)

	child, err := tm.CreateChildTask(CreateChildTaskParams{
		ParentID:    parent.ID,
		AgentName:   "agent-1",
		Description: "bound child",
		TTL:         5 * time.Minute,
		CanDelegate: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Bind a key (clears deadline).
	if err := tm.BindHolderKey(child.ID, testPubKey(0x55)); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	tm.cleanup()

	got := tm.GetTask(child.ID)
	if got == nil {
		t.Error("expected bound child to survive cleanup")
	}
}
