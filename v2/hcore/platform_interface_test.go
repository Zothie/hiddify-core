package hcore

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

type protectionCallback struct {
	libbox.PlatformInterface
	fd  int32
	err error
}

func (p *protectionCallback) AutoDetectInterfaceControl(fd int32) error { p.fd = fd; return p.err }

func TestMobileProtectionMissingPlatform(t *testing.T) {
	p := &MobilePlatformInterface{}
	if !p.UsePlatformAutoDetectInterfaceControl() {
		t.Fatal("missing platform must require protection")
	}
	if err := p.AutoDetectInterfaceControl(42); err == nil {
		t.Fatal("missing platform protection succeeded")
	}
}

func TestMobileProtectionPropagatesError(t *testing.T) {
	denied := errors.New("protection denied")
	for _, err := range []error{nil, denied} {
		callback := &protectionCallback{err: err}
		p := &MobilePlatformInterface{platform: callback}
		if got := p.AutoDetectInterfaceControl(42); !errors.Is(got, err) {
			t.Fatalf("error = %v, want %v", got, err)
		}
		if callback.fd != 42 {
			t.Fatalf("fd = %d, want 42", callback.fd)
		}
	}
}
