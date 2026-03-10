package auth

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// GetPeerCred extracts the caller's UID and PID from a Unix domain socket
// connection using the SO_PEERCRED socket option. Linux only.
func GetPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("peercred: connection is %T, not *net.UnixConn", conn)
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("peercred: SyscallConn: %w", err)
	}

	var cred *syscall.Ucred
	var credErr error

	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("peercred: Control: %w", err)
	}
	if credErr != nil {
		return 0, 0, fmt.Errorf("peercred: GetsockoptUcred: %w", credErr)
	}

	return cred.Uid, cred.Pid, nil
}

// ResolveUsername returns the username for a UID by reading /etc/passwd.
// Falls back to the numeric UID string if lookup fails.
func ResolveUsername(uid uint32) string {
	// Use os/user but avoid cgo dependency by doing a simple fallback.
	// In practice on Linux with glibc this works fine.
	u, err := osUserLookupId(uid)
	if err != nil {
		return fmt.Sprintf("%d", uid)
	}
	return u
}

// osUserLookupId wraps the lookup to avoid importing os/user at the package
// level (keeps the build simple). We read /etc/passwd directly.
func osUserLookupId(uid uint32) (string, error) {
	target := fmt.Sprintf("%d", uid)

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	// Parse lines: username:x:uid:gid:...
	line := ""
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' {
			username, ok := matchPasswdLine(line, target)
			if ok {
				return username, nil
			}
			line = ""
		} else {
			line += string(buf[i])
		}
	}
	if line != "" {
		username, ok := matchPasswdLine(line, target)
		if ok {
			return username, nil
		}
	}

	return "", fmt.Errorf("uid %s not found in /etc/passwd", target)
}

// matchPasswdLine checks if a passwd line has the given UID and returns the username.
func matchPasswdLine(line, uid string) (string, bool) {
	// Format: username:password:uid:gid:gecos:home:shell
	field := 0
	start := 0
	username := ""
	for i := 0; i <= len(line); i++ {
		if i == len(line) || line[i] == ':' {
			switch field {
			case 0:
				username = line[start:i]
			case 2:
				if line[start:i] == uid {
					return username, true
				}
				return "", false
			}
			field++
			start = i + 1
		}
	}
	return "", false
}
