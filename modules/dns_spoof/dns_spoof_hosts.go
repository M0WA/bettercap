package dns_spoof

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/gobwas/glob"

	"github.com/evilsocket/islazy/str"
)

var hostsSplitter = regexp.MustCompile(`\s+`)

type HostEntry struct {
	Host    string
	Suffix  string
	Expr    glob.Glob
    CliExpr glob.Glob
	Address net.IP
    Client  string
}

func (e HostEntry) Matches(host string) bool {
	return e.Host == host || strings.HasSuffix(host, e.Suffix) || (e.Expr != nil && e.Expr.Match(host))
}

func (e HostEntry) MatchesClient(client string) bool {
	return e.Client == client || (e.CliExpr != nil && e.CliExpr.Match(client))
}

type Hosts []HostEntry

func NewHostEntry(host string, address net.IP, client string) HostEntry {
	entry := HostEntry{
		Host:    host,
		Address: address,
	}

	if host[0] == '.' {
		entry.Suffix = host
	} else {
		entry.Suffix = "." + host
	}

	if expr, err := glob.Compile(host); err == nil {
		entry.Expr = expr
	}

	if expr, err := glob.Compile(client); err == nil {
		entry.CliExpr = expr
	}

	return entry
}

func HostsFromFile(filename string, defaultAddress net.IP) (err error, entries []HostEntry) {
	input, err := os.Open(filename)
	if err != nil {
		return
	}
	defer input.Close()

	scanner := bufio.NewScanner(input)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := str.Trim(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
        parts := hostsSplitter.Split(line, 2)
		if len(parts) == 2 {
			address := net.ParseIP(parts[0])
			domain := parts[1]
			entries = append(entries, NewHostEntry(domain, address, ".*"))
		} else if len(parts) == 3 {
			address := net.ParseIP(parts[0])
			domain := parts[1]
			cliaddr := parts[2]
			entries = append(entries, NewHostEntry(domain, address, cliaddr))
        } else {
			entries = append(entries, NewHostEntry(line, defaultAddress, ".*"))
		}
	}

	return
}

func (h Hosts) Resolve(host string,client string) net.IP {
	for _, entry := range h {
		if entry.Matches(host) && entry.MatchesClient(client) {
			return entry.Address
		}
	}
	return nil
}
