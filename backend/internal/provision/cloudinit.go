package provision

import (
	"encoding/json"
	"fmt"
)

// UserData is the server-owned cloud-config for a VM. It is a fixed template with exactly two caller-derived values, both
// validated before use (the hostname is a DNS label, the key is one normalised public key), and both emitted as JSON string
// literals, which are valid YAML scalars, so neither can alter the document structure. It installs the key for the image's
// default cloud user, turns SSH password login off and forbids direct root login. No commands, packages, scripts or users.
func UserData(s Spec) (string, error) {
	if err := s.ValidateExisting(); err != nil { // the seed of a restored or reinstalled VM may belong to a grown disk or changed compute; create applies the stricter lists first
		return "", err
	}
	key, _ := json.Marshal(s.SSHPublicKey)
	host, _ := json.Marshal(s.Name)
	return fmt.Sprintf("#cloud-config\nssh_authorized_keys:\n  - %s\nssh_pwauth: false\ndisable_root: true\nhostname: %s\nmanage_etc_hosts: true\n", key, host), nil
}

// MetaData is the NoCloud meta-data: a unique instance id (the VM's creation UUID) and the hostname.
func MetaData(s Spec) (string, error) {
	if err := s.ValidateExisting(); err != nil { // the seed of a restored or reinstalled VM may belong to a grown disk or changed compute; create applies the stricter lists first
		return "", err
	}
	return fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", s.UUID, s.Name), nil
}
