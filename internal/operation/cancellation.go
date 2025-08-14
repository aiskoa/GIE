package operation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// OperationManager manages cancellable operations
type OperationManager struct {
	mu         sync.RWMutex
	operations map[string]*Operation
	nextID     int
}

// Operation represents a cancellable operation
type Operation struct {
	ID       string
	Type     string // "encrypt" or "decrypt"
	FilePath string
	Context  context.Context
	Cancel   context.CancelFunc
	Status   string
}

var globalManager *OperationManager
var once sync.Once

// GetManager returns the global operation manager
func GetManager() *OperationManager {
	once.Do(func() {
		globalManager = &OperationManager{
			operations: make(map[string]*Operation),
			nextID:     1,
		}
	})
	return globalManager
}

// StartOperation creates and registers a new cancellable operation
func (om *OperationManager) StartOperation(operationType, filePath string) *Operation {
	om.mu.Lock()
	defer om.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	op := &Operation{
		ID:       fmt.Sprintf("op_%d", om.nextID),
		Type:     operationType,
		FilePath: filePath,
		Context:  ctx,
		Cancel:   cancel,
		Status:   "running",
	}

	om.operations[op.ID] = op
	om.nextID++

	return op
}

// CancelOperation cancels an operation by ID
func (om *OperationManager) CancelOperation(operationID string) bool {
	om.mu.Lock()
	defer om.mu.Unlock()

	if op, exists := om.operations[operationID]; exists {
		op.Cancel()
		op.Status = "cancelled"
		return true
	}

	return false
}

// FinishOperation marks an operation as completed and removes it
func (om *OperationManager) FinishOperation(operationID string, status string) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if op, exists := om.operations[operationID]; exists {
		op.Status = status
		// Keep operation for a short time for status checking
		go func() {
			time.Sleep(5 * time.Second)
			om.mu.Lock()
			delete(om.operations, operationID)
			om.mu.Unlock()
		}()
	}
}

// GetOperation returns an operation by ID
func (om *OperationManager) GetOperation(operationID string) (*Operation, bool) {
	om.mu.RLock()
	defer om.mu.RUnlock()

	op, exists := om.operations[operationID]
	return op, exists
}

// GetActiveOperations returns all active operations
func (om *OperationManager) GetActiveOperations() []*Operation {
	om.mu.RLock()
	defer om.mu.RUnlock()

	var active []*Operation
	for _, op := range om.operations {
		if op.Status == "running" {
			active = append(active, op)
		}
	}

	return active
}

// IsCancelled checks if the operation context is cancelled
func (op *Operation) IsCancelled() bool {
	select {
	case <-op.Context.Done():
		return true
	default:
		return false
	}
}

// NewOperation creates a new simple operation for compatibility
func NewOperation() *Operation {
	ctx, cancel := context.WithCancel(context.Background())
	return &Operation{
		ID:      fmt.Sprintf("op_%d", time.Now().UnixNano()),
		Context: ctx,
		Cancel:  cancel,
		Status:  "running",
	}
}
