package hosts

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"

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
)

var (
	clusterRegexp = regexp.MustCompile("^" + dns1123SubdomainRegexp + regexp.QuoteMeta(clusterDomain) + "$")
	appRegexp     = regexp.MustCompile("^" + dns1123SubdomainRegexp + regexp.QuoteMeta(appsDomain) + "$")
)

type Hosts struct {
	File       *libhosty.HostsFile
	HostFilter func(string) bool
}

func init() {
	// goodhosts unconditionally uses this environment variable
	// as an override for the hosts file to use. We don't want admin-helper
	// to modify arbitrary file, so we have to unset it before calling into
	// goodhosts.
	os.Unsetenv("HOSTS_PATH")
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

	line, err := h.findIP(start, end, ip)
	if err != nil {
		return err
	}

	// no host record, need to create new host line
	if line == nil {
		hfl := libhosty.HostsFileLine{
			Type:      libhosty.LineTypeAddress,
			Address:   ip,
			Hostnames: hostEntries,
		}

		// inserts to hosts
		newHosts := make([]libhosty.HostsFileLine, 0)
		newHosts = append(newHosts, h.File.HostsFileLines[:start+1]...)
		newHosts = append(newHosts, hfl)
		newLineNum := len(newHosts) - 1
		newHosts = append(newHosts, h.File.HostsFileLines[start+1:]...)
		h.File.HostsFileLines = newHosts

		// generate raw version of the line
		hfl.Raw = h.File.RenderHostsFileLine(newLineNum)

	} else {
		var hostToAdd []string
		for _, hostName := range hostEntries {
			// check that new host not present in this line
			contains := false
			for _, lineHost := range line.Hostnames {
				if hostName == lineHost {
					contains = true
					break
				}
			}
			// add only new hosts
			if !contains {
				hostToAdd = append(hostToAdd, hostName)
			}
		}
		line.Hostnames = append(line.Hostnames, hostToAdd...)

	}

	return h.File.SaveHostsFile()
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

	start, end, err := h.verifyCrcSection()
	if err != nil {
		return err
	}

	newHosts := make([]libhosty.HostsFileLine, 0)
	newHosts = append(newHosts, h.File.HostsFileLines[:start-1]...)
	newHosts = append(newHosts, h.File.HostsFileLines[end+1:]...)
	// add empty line
	newHosts = append(newHosts, libhosty.HostsFileLine{Type: libhosty.LineTypeEmpty})
	h.File.HostsFileLines = newHosts

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

	if start > 0 && end > 0 {
		return start, end, nil
	}

	hfl, err := libhosty.ParseHostsFileAsString(crcTemplate)
	if err != nil {
		return -1, -1, err
	}

	h.File.HostsFileLines = append(h.File.HostsFileLines, hfl...)

	return h.verifyCrcSection()
}

func (h *Hosts) findIP(start, end int, ip net.IP) (*libhosty.HostsFileLine, error) {
	for i := start; i < end; i++ {
		line := h.File.GetHostsFileLineByRow(i)
		if line.IsCommented {
			continue
		}

		if net.IP.Equal(line.Address, ip) {
			return line, nil
		}
	}

	return nil, nil
}
