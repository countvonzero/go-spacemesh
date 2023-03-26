// Code generated by MockGen. DO NOT EDIT.
// Source: ./interface.go

package bootstrap

import (
	context "context"
	url "net/url"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// Mockhttpclient is a mock of httpclient interface.
type Mockhttpclient struct {
	ctrl     *gomock.Controller
	recorder *MockhttpclientMockRecorder
}

// MockhttpclientMockRecorder is the mock recorder for Mockhttpclient.
type MockhttpclientMockRecorder struct {
	mock *Mockhttpclient
}

// NewMockhttpclient creates a new mock instance.
func NewMockhttpclient(ctrl *gomock.Controller) *Mockhttpclient {
	mock := &Mockhttpclient{ctrl: ctrl}
	mock.recorder = &MockhttpclientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockhttpclient) EXPECT() *MockhttpclientMockRecorder {
	return m.recorder
}

// Query mocks base method.
func (m *Mockhttpclient) Query(arg0 context.Context, arg1 *url.URL) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Query", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query.
func (mr *MockhttpclientMockRecorder) Query(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*Mockhttpclient)(nil).Query), arg0, arg1)
}
