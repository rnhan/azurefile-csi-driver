/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azurefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPasswd(t *testing.T) {
	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"# azfilescomment:x:123:0:\n" +
		"azfiles753940999:x:753940999:753940999:AzureFiles:/nonexistent:/usr/sbin/nologin\n"

	if ok, _ := scanPasswd(content, 0); !ok {
		t.Fatalf("expected uid 0 to be found")
	}
	if ok, n := scanPasswd(content, 753940999); !ok || n != 1 {
		t.Fatalf("expected derived uid found with 1 synthetic entry, got ok=%v n=%d", ok, n)
	}
	if ok, _ := scanPasswd(content, 696363542); ok {
		t.Fatalf("did not expect absent uid to be found")
	}
	// a uid that only appears on a comment line must not match
	if ok, _ := scanPasswd(content, 123); ok {
		t.Fatalf("uid in commented line must be ignored")
	}
}

func withTempPasswd(t *testing.T, initial string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "passwd")
	if err := os.WriteFile(p, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	origPasswd, origLock := hostEtcPasswdPath, hostEtcPasswdLockPath
	hostEtcPasswdPath = p
	hostEtcPasswdLockPath = filepath.Join(dir, ".pwd.lock")
	t.Cleanup(func() {
		hostEtcPasswdPath = origPasswd
		hostEtcPasswdLockPath = origLock
	})
}

func TestEnsurePasswdEntry(t *testing.T) {
	withTempPasswd(t, "root:x:0:0:root:/root:/bin/bash\n")

	// uid 0 is a no-op
	before, _ := os.ReadFile(hostEtcPasswdPath)
	if err := ensurePasswdEntry(0); err != nil {
		t.Fatalf("uid 0 should be a no-op: %v", err)
	}
	if after, _ := os.ReadFile(hostEtcPasswdPath); string(after) != string(before) {
		t.Fatalf("uid 0 must not modify passwd")
	}

	const uid = uint32(753940999)
	if err := ensurePasswdEntry(uid); err != nil {
		t.Fatalf("ensurePasswdEntry: %v", err)
	}
	data, _ := os.ReadFile(hostEtcPasswdPath)
	// gid must equal the uid (dedicated non-root primary group)
	line := fmt.Sprintf("azfiles%d:x:%d:%d:", uid, uid, uid)
	if !strings.Contains(string(data), line) {
		t.Fatalf("entry %q not added: %q", line, data)
	}
	if !strings.Contains(string(data), "/usr/sbin/nologin") {
		t.Fatalf("entry must be a no-login account: %q", data)
	}

	// idempotent: a second call must not append a duplicate
	if err := ensurePasswdEntry(uid); err != nil {
		t.Fatalf("second call: %v", err)
	}
	data, _ = os.ReadFile(hostEtcPasswdPath)
	if c := strings.Count(string(data), fmt.Sprintf(":%d:%d:", uid, uid)); c != 1 {
		t.Fatalf("expected exactly 1 entry for uid, got %d: %q", c, data)
	}
}

func TestEnsurePasswdEntryMissingTrailingNewline(t *testing.T) {
	withTempPasswd(t, "root:x:0:0:root:/root:/bin/bash") // no trailing newline

	const uid = uint32(42)
	if err := ensurePasswdEntry(uid); err != nil {
		t.Fatalf("ensurePasswdEntry: %v", err)
	}
	data, _ := os.ReadFile(hostEtcPasswdPath)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected the root line to stay intact plus one new line, got %d: %q", len(lines), data)
	}
	if !strings.HasPrefix(lines[1], fmt.Sprintf("azfiles%d:", uid)) {
		t.Fatalf("new entry malformed: %q", data)
	}
}

func TestEnsurePasswdEntryExistingRealUID(t *testing.T) {
	// a uid already owned by a real account must not be duplicated
	withTempPasswd(t, "root:x:0:0:root:/root:/bin/bash\nalice:x:42:42:alice:/home/alice:/bin/bash\n")

	if err := ensurePasswdEntry(42); err != nil {
		t.Fatalf("ensurePasswdEntry: %v", err)
	}
	data, _ := os.ReadFile(hostEtcPasswdPath)
	if strings.Contains(string(data), "azfiles42") {
		t.Fatalf("must not add a synthetic entry when the uid already exists: %q", data)
	}
}

func TestEnsurePasswdEntryMissingFile(t *testing.T) {
	withTempPasswd(t, "root:x:0:0:root:/root:/bin/bash\n")
	if err := os.Remove(hostEtcPasswdPath); err != nil {
		t.Fatal(err)
	}
	// fail closed when the passwd file cannot be read for a non-zero uid
	if err := ensurePasswdEntry(42); err == nil {
		t.Fatalf("expected error when passwd file is missing")
	}
	// uid 0 stays a no-op even if the path is bad
	if err := ensurePasswdEntry(0); err != nil {
		t.Fatalf("uid 0 must not touch the file: %v", err)
	}
}
