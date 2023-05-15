// Code generated by MockGen. DO NOT EDIT.
// Source: ./log.go

// Package log is a generated GoMock package.
package log

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockLogger is a mock of Logger interface.
type MockLogger struct {
	ctrl     *gomock.Controller
	recorder *MockLoggerMockRecorder
}

// MockLoggerMockRecorder is the mock recorder for MockLogger.
type MockLoggerMockRecorder struct {
	mock *MockLogger
}

// NewMockLogger creates a new mock instance.
func NewMockLogger(ctrl *gomock.Controller) *MockLogger {
	mock := &MockLogger{ctrl: ctrl}
	mock.recorder = &MockLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLogger) EXPECT() *MockLoggerMockRecorder {
	return m.recorder
}

// Debug mocks base method.
func (m *MockLogger) Debug(format string, args ...any) {
	m.ctrl.T.Helper()
	varargs := []interface{}{format}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debug", varargs...)
}

// Debug indicates an expected call of Debug.
func (mr *MockLoggerMockRecorder) Debug(format interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{format}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debug", reflect.TypeOf((*MockLogger)(nil).Debug), varargs...)
}

// Error mocks base method.
func (m *MockLogger) Error(format string, args ...any) {
	m.ctrl.T.Helper()
	varargs := []interface{}{format}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Error", varargs...)
}

// Error indicates an expected call of Error.
func (mr *MockLoggerMockRecorder) Error(format interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{format}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Error", reflect.TypeOf((*MockLogger)(nil).Error), varargs...)
}

// Info mocks base method.
func (m *MockLogger) Info(format string, args ...any) {
	m.ctrl.T.Helper()
	varargs := []interface{}{format}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Info", varargs...)
}

// Info indicates an expected call of Info.
func (mr *MockLoggerMockRecorder) Info(format interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{format}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Info", reflect.TypeOf((*MockLogger)(nil).Info), varargs...)
}

// Panic mocks base method.
func (m *MockLogger) Panic(format string, args ...any) {
	m.ctrl.T.Helper()
	varargs := []interface{}{format}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Panic", varargs...)
}

// Panic indicates an expected call of Panic.
func (mr *MockLoggerMockRecorder) Panic(format interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{format}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Panic", reflect.TypeOf((*MockLogger)(nil).Panic), varargs...)
}

// Warning mocks base method.
func (m *MockLogger) Warning(format string, args ...any) {
	m.ctrl.T.Helper()
	varargs := []interface{}{format}
	for _, a := range args {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Warning", varargs...)
}

// Warning indicates an expected call of Warning.
func (mr *MockLoggerMockRecorder) Warning(format interface{}, args ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{format}, args...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Warning", reflect.TypeOf((*MockLogger)(nil).Warning), varargs...)
}

// With mocks base method.
func (m *MockLogger) With() FieldLogger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "With")
	ret0, _ := ret[0].(FieldLogger)
	return ret0
}

// With indicates an expected call of With.
func (mr *MockLoggerMockRecorder) With() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "With", reflect.TypeOf((*MockLogger)(nil).With))
}

// WithContext mocks base method.
func (m *MockLogger) WithContext(arg0 context.Context) Log {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithContext", arg0)
	ret0, _ := ret[0].(Log)
	return ret0
}

// WithContext indicates an expected call of WithContext.
func (mr *MockLoggerMockRecorder) WithContext(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithContext", reflect.TypeOf((*MockLogger)(nil).WithContext), arg0)
}

// WithName mocks base method.
func (m *MockLogger) WithName(arg0 string) Log {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithName", arg0)
	ret0, _ := ret[0].(Log)
	return ret0
}

// WithName indicates an expected call of WithName.
func (mr *MockLoggerMockRecorder) WithName(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithName", reflect.TypeOf((*MockLogger)(nil).WithName), arg0)
}