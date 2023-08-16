// Code generated by MockGen. DO NOT EDIT.
// Source: ./blocks.go

// Package blockssync is a generated GoMock package.
package blockssync

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	types "github.com/spacemeshos/go-spacemesh/common/types"
)

// MockblockFetcher is a mock of blockFetcher interface.
type MockblockFetcher struct {
	ctrl     *gomock.Controller
	recorder *MockblockFetcherMockRecorder
}

// MockblockFetcherMockRecorder is the mock recorder for MockblockFetcher.
type MockblockFetcherMockRecorder struct {
	mock *MockblockFetcher
}

// NewMockblockFetcher creates a new mock instance.
func NewMockblockFetcher(ctrl *gomock.Controller) *MockblockFetcher {
	mock := &MockblockFetcher{ctrl: ctrl}
	mock.recorder = &MockblockFetcherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockblockFetcher) EXPECT() *MockblockFetcherMockRecorder {
	return m.recorder
}

// GetBlocks mocks base method.
func (m *MockblockFetcher) GetBlocks(arg0 context.Context, arg1 []types.BlockID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBlocks", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// GetBlocks indicates an expected call of GetBlocks.
func (mr *MockblockFetcherMockRecorder) GetBlocks(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBlocks", reflect.TypeOf((*MockblockFetcher)(nil).GetBlocks), arg0, arg1)
}