package hosts

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
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

	uniqueHosts := map[string]bool{}
	for i := 0; i < len(hosts); i++ {
		uniqueHosts[hosts[i]] = true
	}

	var hostEntries []string
	for key := range uniqueHosts {
		hostEntries = append(hostEntries, key)
	}

	sort.Strings(hostEntries)

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

	// no host record, need to create new host line
	if lines == nil {
		multiLineHosts := ChunkSlice(hostEntries, maxHostsInLine)
		for _, hosts := range multiLineHosts {
			h.createAndAddHostsLine(ip, hosts, start)
		}
	} else {
		h.addHostToExistingLines(hostEntries, start, end, lines, ip)
	}

	return h.File.SaveHostsFile()
}

func (h *Hosts) addHostToExistingLines(hostEntries []string, start int, end int, lines []*libhosty.HostsFileLine, ip net.IP) {
	// check that host not present already
	var hostToAdd []string
	for _, hostName := range hostEntries {
		if !h.lineContains(hostName, start, end) {
			hostToAdd = append(hostToAdd, hostName)
		}
	}
	for _, line := range lines {
		// check if our line has more than maxHostsInLine hosts and rewrite it to fit maxHostsInLine
		if len(line.Hostnames) > maxHostsInLine {
			hostToAdd = append(line.Hostnames[maxHostsInLine:], hostToAdd...)
			line.Hostnames = line.Hostnames[0:maxHostsInLine]
		}
		if len(hostToAdd)+len(line.Hostnames) > maxHostsInLine {

			fittingNumOfRecords := maxHostsInLine - len(line.Hostnames)
			if fittingNumOfRecords > len(hostToAdd) {
				fittingNumOfRecords = len(hostToAdd)
			}

			hostsForExistingLine := hostToAdd[0:fittingNumOfRecords]
			line.Hostnames = append(line.Hostnames, hostsForExistingLine...)
			hostToAdd = hostToAdd[fittingNumOfRecords:]

		} else {
			line.Hostnames = append(line.Hostnames, hostToAdd...)
			hostToAdd = nil
		}
	}

	if len(hostToAdd) > 0 {
		h.createAndAddHostsLine(ip, hostToAdd, lines[len(lines)-1].Number)
	}
}

func (h *Hosts) createAndAddHostsLine(ip net.IP, hosts []string, sectionStart int) {
	hfl := libhosty.HostsFileLine{
		Type:      libhosty.LineTypeAddress,
		Address:   ip,
		Hostnames: hosts,
	}

	// inserts to hosts
	newHosts := make([]libhosty.HostsFileLine, 0)
	newHosts = append(newHosts, h.File.HostsFileLines[:sectionStart+1]...)
	newHosts = append(newHosts, hfl)
	newLineNum := len(newHosts) - 1
	newHosts = append(newHosts, h.File.HostsFileLines[sectionStart+1:]...)
	h.File.HostsFileLines = newHosts

	// generate raw version of the line
	hfl.Raw = h.File.RenderHostsFileLine(newLineNum)
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

	start, end, err := h.verifyCrcSection()
	if err != nil {
		return err
	}

	h.Lock()
	defer h.Unlock()
	for i := start; i < end; i++ {
		line := h.File.GetHostsFileLineByRow(i)
		if line.Type == libhosty.LineTypeComment {
			continue
		}

		for hostIdx, hostname := range line.Hostnames {
			if _, ok := hostEntries[hostname]; ok {
				if len(line.Hostnames) > 1 {
					line.Hostnames = append(line.Hostnames[:hostIdx], line.Hostnames[hostIdx+1:]...)
				}

				// remove the line if there are no more hostnames (other than the actual one)
				if len(line.Hostnames) < 1 {
					h.File.RemoveHostsFileLineByRow(i)
				}
			}

		}
	}

	return h.File.SaveHostsFile()
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
	} else {
		return -1, -1, fmt.Errorf("can't add CRC section, check hosts file")
	}
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
