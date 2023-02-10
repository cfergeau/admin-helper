package hosts

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/areYouLazy/libhosty"
)

const (
	// source https://github.com/kubernetes/apimachinery/blob/603e04655e9f537eb01238cdbce4891f832a4f27/pkg/util/validation/validation.go#L208
	dns1123SubdomainRegexp = `[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*`
	clusterDomain          = ".crc.testing"
	appsDomain             = ".apps-crc.testing"

	crcTemplate = `# Added by CRC
# End of CRC section
`
	maxHostsInLine = 9
)

var (
	clusterRegexp = regexp.MustCompile("^" + dns1123SubdomainRegexp + regexp.QuoteMeta(clusterDomain) + "$")
	appRegexp     = regexp.MustCompile("^" + dns1123SubdomainRegexp + regexp.QuoteMeta(appsDomain) + "$")
)

type Hosts struct {
	sync.Mutex
	File       *libhosty.HostsFile
	HostFilter func(string) bool
}

func New() (*Hosts, error) {
	file, err := libhosty.Init()
	if err != nil {
		return nil, err
	}

	return &Hosts{
		File:       file,
		HostFilter: defaultFilter,
	}, nil
}

func defaultFilter(s string) bool {
	return clusterRegexp.MatchString(s) || appRegexp.MatchString(s)
}

func (h *Hosts) Add(ipRaw string, hosts []string) error {
	if err := h.verifyHosts(hosts); err != nil {
		return err
	}

	if err := h.checkIsWritable(); err != nil {
		return err
	}

	// parse ip to net.IP
	ip := net.ParseIP(ipRaw)
	if ip == nil {
		return libhosty.ErrCannotParseIPAddress(ipRaw)
	}

	start, end, err := h.verifyCrcSection()
	if err != nil {
		return err
	}

	lines, err := h.findIP(start, end, ip)
	if err != nil {
		return err
	}

	h.Lock()
	defer h.Unlock()

	hostnames := [][]string{}
	for _, line := range lines {
		hostnames = append(hostnames, line.Hostnames)
	}
	hostnames = append(hostnames, hosts)

	hostsFileLines := []libhosty.HostsFileLine{}
	hostsFileLines = append(hostsFileLines, h.File.HostsFileLines[:start+1]...)
	for _, lineContent := range ChunkSlices(maxHostsInLine, hostnames...) {
		hostsFileLines = append(hostsFileLines, newHostsFileLine(ip, lineContent))
	}
	hostsFileLines = append(hostsFileLines, h.File.HostsFileLines[end:]...)
	h.File.HostsFileLines = hostsFileLines

	return h.File.SaveHostsFile()
}

func newHostsFileLine(ip net.IP, hostEntries []string) libhosty.HostsFileLine {
	return libhosty.HostsFileLine{
		Type:      libhosty.LineTypeAddress,
		Address:   ip,
		Hostnames: hostEntries,
	}
}

func (h *Hosts) Remove(hosts []string) error {
	if err := h.verifyHosts(hosts); err != nil {
		return err
	}

	if err := h.checkIsWritable(); err != nil {
		return err
	}

	uniqueHosts := map[string]bool{}
	for i := 0; i < len(hosts); i++ {
		uniqueHosts[hosts[i]] = true
	}

	var hostEntries = make(map[string]struct{}, len(uniqueHosts))

	for key := range uniqueHosts {
		hostEntries[key] = struct{}{}
	}

	start, end := h.findCrcSection()

	h.Lock()
	defer h.Unlock()
	// delete from CRC section
	if start > 0 && end > 0 {
		for i := start; i < end; i++ {
			line := h.File.GetHostsFileLineByRow(i)
			if line.Type == libhosty.LineTypeComment {
				continue
			}

			for hostIdx, hostname := range line.Hostnames {
				if _, ok := hostEntries[hostname]; ok {
					h.removeHostFromLine(line, hostIdx, i)
				}

			}
		}
	} else {
		// CRC section not present, delete hosts from entire file
		for _, host := range hosts {
			lineIdx, _, err := h.File.LookupByHostname(host)
			if err != nil {
				continue
			}

			line := h.File.GetHostsFileLineByRow(lineIdx)

			for hostIdx, hostname := range line.Hostnames {
				if hostname == host {
					h.removeHostFromLine(line, hostIdx, lineIdx)
					break
				}

			}

		}
	}

	return h.File.SaveHostsFile()
}

func (h *Hosts) removeHostFromLine(line *libhosty.HostsFileLine, hostIdx int, i int) {
	if len(line.Hostnames) >= 1 {
		line.Hostnames = append(line.Hostnames[:hostIdx], line.Hostnames[hostIdx+1:]...)
	}

	// remove the line if there are no more hostnames (other than the actual one)
	if len(line.Hostnames) < 1 {
		h.File.RemoveHostsFileLineByRow(i)
	}
}

func (h *Hosts) Clean() error {
	if err := h.checkIsWritable(); err != nil {
		return err
	}

	h.Lock()
	defer h.Unlock()

	start, end := h.findCrcSection()
	// no CRC section present
	if start == -1 && end == -1 {
		return nil
	}

	var newHosts []libhosty.HostsFileLine

	newHosts = append(newHosts, h.File.HostsFileLines[:start-1]...)
	newHosts = append(newHosts, h.File.HostsFileLines[end+1:]...)
	h.File.HostsFileLines = newHosts

	_, _, emptyLineErr := h.File.AddEmptyFileLine()
	if emptyLineErr != nil {
		return emptyLineErr
	}

	return h.File.SaveHostsFile()
}

func (h *Hosts) checkIsWritable() error {
	file, err := os.OpenFile(h.File.Config.FilePath, os.O_WRONLY, 0660)
	if err != nil {
		return fmt.Errorf("host file not writable, try running with elevated privileges")
	}
	defer file.Close()
	return nil
}

func (h *Hosts) Contains(ip, host string) bool {
	if err := h.verifyHosts([]string{host}); err != nil {
		return false
	}

	lines := h.File.GetHostsFileLinesByAddress(ip)

	for _, line := range lines {
		for _, h := range line.Hostnames {
			if h == host {
				return true
			}
		}
	}

	return false
}

func (h *Hosts) verifyHosts(hosts []string) error {
	for _, host := range hosts {
		if !h.HostFilter(host) {
			return fmt.Errorf("input %s rejected", host)
		}
	}
	return nil
}

func (h *Hosts) verifyCrcSection() (int, int, error) {

	start, end := h.findCrcSection()

	if start > 0 && end > 0 {
		return start, end, nil
	}

	hfl, err := libhosty.ParseHostsFileAsString(crcTemplate)
	if err != nil {
		return -1, -1, err
	}

	h.File.HostsFileLines = append(h.File.HostsFileLines, hfl...)

	start, end = h.findCrcSection()

	if start > 0 && end > 0 {
		return start, end, nil
	}

	return -1, -1, fmt.Errorf("can't add CRC section, check hosts file")
}

func (h *Hosts) findCrcSection() (int, int) {
	start := -1
	end := -1

	for i, line := range h.File.HostsFileLines {
		if line.Type == libhosty.LineTypeComment {
			if strings.Contains(line.Raw, "Added by CRC") {
				start = i
				continue
			}

			if strings.Contains(line.Raw, "End of CRC section") {
				end = i
				break
			}

		}
	}

	return start, end
}

func (h *Hosts) findIP(start, end int, ip net.IP) ([]*libhosty.HostsFileLine, error) {
	var result []*libhosty.HostsFileLine
	for i := start; i < end; i++ {
		line := h.File.GetHostsFileLineByRow(i)
		if line.Type == libhosty.LineTypeComment {
			continue
		}

		if net.IP.Equal(line.Address, ip) {
			result = append(result, line)
		}
	}

	return result, nil
}

func (h *Hosts) lineContains(hostName string, sectionStart, sectionEnd int) bool {
	lineNum, _ := h.File.GetHostsFileLineByHostname(hostName)
	return lineNum > sectionStart && lineNum < sectionEnd
}
