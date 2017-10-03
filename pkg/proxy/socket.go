// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func listenSocket(address string, mark int) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	family := syscall.AF_INET
	if addr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("unable to set SO_REUSEADDR socket option: %s", err)
	}

	setFdMark(fd, mark)

	sockAddr, err := ipToSockaddr(family, addr.IP, addr.Port, addr.Zone)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Bind(fd, sockAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), addr.String())
	defer f.Close()

	return net.FileListener(f)
}

func lookupNewDestFromHttp(req *http.Request, dport uint16) (uint32, string, error) {
	return lookupNewDest(req.RemoteAddr, dport)
}

func lookupNewDest(remoteAddr string, dport uint16) (uint32, string, error) {
	ip, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid remote address: %s", err)
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return 0, "", fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("unable to parse port string: %s", err)
	}

	if pIP.To4() != nil {
		key := &Proxy4Key{
			SPort:   uint16(sport),
			DPort:   dport,
			Nexthdr: 6,
		}

		copy(key.SAddr[:], pIP.To4())

		val, err := LookupEgress4(key)
		if err != nil {
			return 0, "", fmt.Errorf("Unable to find IPv4 proxy entry for %s: %s", key, err)
		}

		log.Debugf("Found IPv4 proxy entry: %+v", val)
		return val.SourceIdentity, val.HostPort(), nil
	}

	key := &Proxy6Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To16())

	val, err := LookupEgress6(key)
	if err != nil {
		return 0, "", fmt.Errorf("Unable to find IPv6 proxy entry for %s: %s", key, err)
	}

	log.Debugf("Found IPv6 proxy entry: %+v", val)
	return val.SourceIdentity, val.HostPort(), nil
}

type proxyIdentity int

const identityKey proxyIdentity = 0

func newIdentityContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func identityFromContext(ctx context.Context) (int, bool) {
	val, ok := ctx.Value(identityKey).(int)
	return val, ok
}

func setFdMark(fd, mark int) {
	log.WithFields(log.Fields{
		fieldFd:     fd,
		fieldMarker: mark,
	}).Debug("Setting packet marker of socket")

	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	if err != nil {
		log.WithFields(log.Fields{
			fieldFd:     fd,
			fieldMarker: mark,
		}).WithError(err).Warning("Unable to set SO_MARK")
	}
}

func setSocketMark(c net.Conn, mark int) {
	if tc, ok := c.(*net.TCPConn); ok {
		if f, err := tc.File(); err == nil {
			defer f.Close()
			setFdMark(int(f.Fd()), mark)
		}
	}
}
