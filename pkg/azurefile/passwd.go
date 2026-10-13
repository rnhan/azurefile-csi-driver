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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// cifs.upcall is a kernel usermode helper and always runs in the host mount
// namespace, so the per-identity cruid must be resolvable in the host passwd
// db.
var (
	hostEtcPasswdPath = "/host/etc/passwd"
	// hostEtcPasswdLockPath is the shadow-utils lock file, so our append
	// serializes against useradd/usermod/vipw and other NodeStageVolumes.
	hostEtcPasswdLockPath = "/host/etc/.pwd.lock"
)

const (
	// syntheticPasswdUserPrefix names the placeholder accounts we add. The uid is
	// appended so the login name is unique and self-describing.
	syntheticPasswdUserPrefix = "azfiles"
	// maxSyntheticPasswdEntries caps how many placeholder accounts we will add to
	// a node for distinct identities.
	maxSyntheticPasswdEntries = 10000
)

// passwdMu serializes passwd mutations inside this process. lockHostPasswd
// (on-disk fcntl) serializes against other host tooling.
var passwdMu sync.Mutex

// ensurePasswdEntry makes a per-identity Kerberos credential uid resolvable via
// getpwuid on the node. cifs.upcall calls getpwuid(cruid) before it reads the
// credential cache (krb5cc_<cruid>).  A cruid with no passwd entry makes the
// upcall abort ("failed to retrieve GID from UID <uid>") and the mount fails.
//
// The placeholder is a locked, no-login account whose only purpose is to
// satisfy the getpwuid lookup.
func ensurePasswdEntry(uid uint32) error {
	if uid == 0 {
		return nil
	}

	passwdMu.Lock()
	defer passwdMu.Unlock()

	unlock, err := lockHostPasswd()
	if err != nil {
		return fmt.Errorf("acquire passwd lock %s: %w", hostEtcPasswdLockPath, err)
	}
	defer unlock()

	data, err := os.ReadFile(hostEtcPasswdPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostEtcPasswdPath, err)
	}
	content := string(data)

	exists, azfilesCount := scanPasswd(content, uid)
	if exists {
		return nil
	}
	if azfilesCount >= maxSyntheticPasswdEntries {
		return fmt.Errorf("refusing to add Kerberos credential uid %d: %d azfiles* passwd entries already present on the node (max %d)",
			uid, azfilesCount, maxSyntheticPasswdEntries)
	}

	// Preserve a well-formed file if the last line lacks a trailing newline.
	var lead string
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		lead = "\n"
	}
	entry := fmt.Sprintf("%s%s%d:x:%d:%d:AzureFiles Kerberos per-identity credential cache:/nonexistent:/usr/sbin/nologin\n",
		lead, syntheticPasswdUserPrefix, uid, uid, uid)

	f, err := os.OpenFile(hostEtcPasswdPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open %s for append: %w", hostEtcPasswdPath, err)
	}
	if _, err := f.WriteString(entry); err != nil {
		_ = f.Close()
		return fmt.Errorf("append passwd entry for uid %d: %w", uid, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", hostEtcPasswdPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", hostEtcPasswdPath, err)
	}

	// Verify the entry.
	verify, err := os.ReadFile(hostEtcPasswdPath)
	if err != nil {
		return fmt.Errorf("verify %s: %w", hostEtcPasswdPath, err)
	}
	if ok, _ := scanPasswd(string(verify), uid); !ok {
		return fmt.Errorf("passwd entry for uid %d not present after write", uid)
	}
	klog.V(2).Infof("ensured host passwd entry %s%d for Kerberos credential uid", syntheticPasswdUserPrefix, uid)
	return nil
}

// scanPasswd reports whether uid already appears in the passwd content (its
// third, numeric-uid field) and counts azfiles* placeholder accounts present.
func scanPasswd(content string, uid uint32) (exists bool, azfilesCount int) {
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(content, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == want {
			exists = true
		}
		if strings.HasPrefix(fields[0], syntheticPasswdUserPrefix) {
			azfilesCount++
		}
	}
	return exists, azfilesCount
}

// passwdLockTimeout bounds how long we wait for the shadow-utils passwd lock,
// waiting passwdLockRetryDelay between attempts, mirroring lckpwdf(3)'s wait so
// a stuck lock fails the mount instead of blocking indefinitely.
const (
	passwdLockTimeout    = 15 * time.Second
	passwdLockRetryDelay = 100 * time.Millisecond
)

// lockHostPasswd takes the shadow-utils passwd lock (fcntl write lock on
// /etc/.pwd.lock, equivalent to lckpwdf(3), coordinates with
// useradd/usermod/vipw). Returned func releases the lock. Poll the
// non-blocking F_SETLK up to passwdLockTimeout.
func lockHostPasswd() (func(), error) {
	f, err := os.OpenFile(hostEtcPasswdLockPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
	deadline := time.Now().Add(passwdLockTimeout)
	for {
		switch err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk); err {
		case nil:
			return func() {
				ulk := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0}
				_ = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &ulk)
				_ = f.Close()
			}, nil
		case unix.EAGAIN, unix.EACCES, unix.EINTR:
		default:
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("timed out after %s waiting for %s", passwdLockTimeout, hostEtcPasswdLockPath)
		}
		time.Sleep(passwdLockRetryDelay)
	}
}
