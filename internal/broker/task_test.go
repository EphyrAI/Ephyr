package broker

import (
	"sync"
	"testing"
	"time"

	"github.com/sprawl/clauth/internal/policy"
	"github.com/sprawl/clauth/internal/token"
)

func TestCreateRootTask(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task := tm.CreateTask(CreateTaskParams{
		AgentName:   "agent-1",
		Description: "test task",
		TTL:         5 * time.Minute,
		InitiatedBy: "clauth:local:uid:1000",
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
	if task.InitiatedBy != "clauth:local:uid:1000" {
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
