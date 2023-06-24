// Code generated by MockGen. DO NOT EDIT.
// Source: ./interface.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	types "github.com/spacemeshos/go-spacemesh/common/types"
	log "github.com/spacemeshos/go-spacemesh/log"
)

// MocklayerPatrol is a mock of layerPatrol interface.
type MocklayerPatrol struct {
	ctrl     *gomock.Controller
	recorder *MocklayerPatrolMockRecorder
}

// MocklayerPatrolMockRecorder is the mock recorder for MocklayerPatrol.
type MocklayerPatrolMockRecorder struct {
	mock *MocklayerPatrol
}

// NewMocklayerPatrol creates a new mock instance.
func NewMocklayerPatrol(ctrl *gomock.Controller) *MocklayerPatrol {
	mock := &MocklayerPatrol{ctrl: ctrl}
	mock.recorder = &MocklayerPatrolMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocklayerPatrol) EXPECT() *MocklayerPatrolMockRecorder {
	return m.recorder
}

// CompleteHare mocks base method.
func (m *MocklayerPatrol) CompleteHare(arg0 types.LayerID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CompleteHare", arg0)
}

// CompleteHare indicates an expected call of CompleteHare.
func (mr *MocklayerPatrolMockRecorder) CompleteHare(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CompleteHare", reflect.TypeOf((*MocklayerPatrol)(nil).CompleteHare), arg0)
}

// MockmeshProvider is a mock of meshProvider interface.
type MockmeshProvider struct {
	ctrl     *gomock.Controller
	recorder *MockmeshProviderMockRecorder
}

// MockmeshProviderMockRecorder is the mock recorder for MockmeshProvider.
type MockmeshProviderMockRecorder struct {
	mock *MockmeshProvider
}

// NewMockmeshProvider creates a new mock instance.
func NewMockmeshProvider(ctrl *gomock.Controller) *MockmeshProvider {
	mock := &MockmeshProvider{ctrl: ctrl}
	mock.recorder = &MockmeshProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockmeshProvider) EXPECT() *MockmeshProviderMockRecorder {
	return m.recorder
}

// AddBlockWithTXs mocks base method.
func (m *MockmeshProvider) AddBlockWithTXs(arg0 context.Context, arg1 *types.Block) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddBlockWithTXs", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddBlockWithTXs indicates an expected call of AddBlockWithTXs.
func (mr *MockmeshProviderMockRecorder) AddBlockWithTXs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBlockWithTXs", reflect.TypeOf((*MockmeshProvider)(nil).AddBlockWithTXs), arg0, arg1)
}

// ProcessLayerPerHareOutput mocks base method.
func (m *MockmeshProvider) ProcessLayerPerHareOutput(arg0 context.Context, arg1 types.LayerID, arg2 types.BlockID, arg3 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProcessLayerPerHareOutput", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProcessLayerPerHareOutput indicates an expected call of ProcessLayerPerHareOutput.
func (mr *MockmeshProviderMockRecorder) ProcessLayerPerHareOutput(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessLayerPerHareOutput", reflect.TypeOf((*MockmeshProvider)(nil).ProcessLayerPerHareOutput), arg0, arg1, arg2, arg3)
}

// Mockexecutor is a mock of executor interface.
type Mockexecutor struct {
	ctrl     *gomock.Controller
	recorder *MockexecutorMockRecorder
}

// MockexecutorMockRecorder is the mock recorder for Mockexecutor.
type MockexecutorMockRecorder struct {
	mock *Mockexecutor
}

// NewMockexecutor creates a new mock instance.
func NewMockexecutor(ctrl *gomock.Controller) *Mockexecutor {
	mock := &Mockexecutor{ctrl: ctrl}
	mock.recorder = &MockexecutorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockexecutor) EXPECT() *MockexecutorMockRecorder {
	return m.recorder
}

// ExecuteOptimistic mocks base method.
func (m *Mockexecutor) ExecuteOptimistic(arg0 context.Context, arg1 types.LayerID, arg2 uint64, arg3 []types.AnyReward, arg4 []types.TransactionID) (*types.Block, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecuteOptimistic", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*types.Block)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecuteOptimistic indicates an expected call of ExecuteOptimistic.
func (mr *MockexecutorMockRecorder) ExecuteOptimistic(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecuteOptimistic", reflect.TypeOf((*Mockexecutor)(nil).ExecuteOptimistic), arg0, arg1, arg2, arg3, arg4)
}

// MocklayerClock is a mock of layerClock interface.
type MocklayerClock struct {
	ctrl     *gomock.Controller
	recorder *MocklayerClockMockRecorder
}

// MocklayerClockMockRecorder is the mock recorder for MocklayerClock.
type MocklayerClockMockRecorder struct {
	mock *MocklayerClock
}

// NewMocklayerClock creates a new mock instance.
func NewMocklayerClock(ctrl *gomock.Controller) *MocklayerClock {
	mock := &MocklayerClock{ctrl: ctrl}
	mock.recorder = &MocklayerClockMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocklayerClock) EXPECT() *MocklayerClockMockRecorder {
	return m.recorder
}

// AwaitLayer mocks base method.
func (m *MocklayerClock) AwaitLayer(layerID types.LayerID) chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AwaitLayer", layerID)
	ret0, _ := ret[0].(chan struct{})
	return ret0
}

// AwaitLayer indicates an expected call of AwaitLayer.
func (mr *MocklayerClockMockRecorder) AwaitLayer(layerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AwaitLayer", reflect.TypeOf((*MocklayerClock)(nil).AwaitLayer), layerID)
}

// CurrentLayer mocks base method.
func (m *MocklayerClock) CurrentLayer() types.LayerID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentLayer")
	ret0, _ := ret[0].(types.LayerID)
	return ret0
}

// CurrentLayer indicates an expected call of CurrentLayer.
func (mr *MocklayerClockMockRecorder) CurrentLayer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentLayer", reflect.TypeOf((*MocklayerClock)(nil).CurrentLayer))
}

// Mockcertifier is a mock of certifier interface.
type Mockcertifier struct {
	ctrl     *gomock.Controller
	recorder *MockcertifierMockRecorder
}

// MockcertifierMockRecorder is the mock recorder for Mockcertifier.
type MockcertifierMockRecorder struct {
	mock *Mockcertifier
}

// NewMockcertifier creates a new mock instance.
func NewMockcertifier(ctrl *gomock.Controller) *Mockcertifier {
	mock := &Mockcertifier{ctrl: ctrl}
	mock.recorder = &MockcertifierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockcertifier) EXPECT() *MockcertifierMockRecorder {
	return m.recorder
}

// CertifyIfEligible mocks base method.
func (m *Mockcertifier) CertifyIfEligible(arg0 context.Context, arg1 log.Log, arg2 types.LayerID, arg3 types.BlockID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CertifyIfEligible", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// CertifyIfEligible indicates an expected call of CertifyIfEligible.
func (mr *MockcertifierMockRecorder) CertifyIfEligible(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CertifyIfEligible", reflect.TypeOf((*Mockcertifier)(nil).CertifyIfEligible), arg0, arg1, arg2, arg3)
}

// RegisterForCert mocks base method.
func (m *Mockcertifier) RegisterForCert(arg0 context.Context, arg1 types.LayerID, arg2 types.BlockID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterForCert", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterForCert indicates an expected call of RegisterForCert.
func (mr *MockcertifierMockRecorder) RegisterForCert(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterForCert", reflect.TypeOf((*Mockcertifier)(nil).RegisterForCert), arg0, arg1, arg2)
}
