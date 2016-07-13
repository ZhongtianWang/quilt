package network

import (
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/NetSys/quilt/db"
	"github.com/NetSys/quilt/minion/ovsdb"
)

var testSwitch = "testSwitch"

func TestACL(t *testing.T) {
	client := ovsdb.NewFakeOvsdbClient()
	client.CreateLogicalSwitch(lSwitch)
	ovsdb.Open = func() (ovsdb.Client, error) {
		return client, nil
	}

	defaultRules := []ovsdb.AclCore{
		{
			Priority:  0,
			Match:     "ip",
			Action:    "drop",
			Direction: "to-lport"},

		{
			Priority:  0,
			Match:     "ip",
			Action:    "drop",
			Direction: "from-lport"},
	}

	// `expACLs` should NOT contain the default rules.
	checkAcl := func(connections []db.Connection, labels []db.Label,
		containers []db.Container, coreExpACLs []ovsdb.AclCore,
		resetClient bool) {
		if resetClient {
			client = ovsdb.NewFakeOvsdbClient()
			client.CreateLogicalSwitch(lSwitch)
		}
		updateACLs(connections, labels, containers)

		res, err := client.ListACLs(lSwitch)
		if err != nil {
			t.Error(err)
		}
		coreExpACLs = append(defaultRules, coreExpACLs...)

		var expACLs []ovsdb.Acl
		for _, core := range coreExpACLs {
			expACLs = append(expACLs, ovsdb.Acl{
				Core: core,
			})
		}

		updateACLs(connections, labels, containers)
		res, err = client.ListACLs(testSwitch)
		if err != nil {
			t.Error(err)
		}
		sort.Sort(ACLList(expACLs))
		sort.Sort(ACLList(res))
		if !reflect.DeepEqual(expACLs, res) {
			_, _, callerLine, _ := runtime.Caller(1)
			t.Errorf("Test at line %d failed. Expected %v, got %v.",
				callerLine, expACLs, res)
		}
	}

	redLabelIP := "8.8.8.8"
	blueLabelIP := "9.9.9.9"
	yellowLabelIP := "10.10.10.10"
	purpleLabelIP := "12.12.12.12"
	redBlueLabelIP := "13.13.13.13"
	redLabel := db.Label{Label: "red",
		IP: redLabelIP}
	blueLabel := db.Label{Label: "blue",
		IP: blueLabelIP}
	yellowLabel := db.Label{Label: "yellow",
		IP: yellowLabelIP}
	purpleLabel := db.Label{Label: "purple",
		IP: purpleLabelIP}
	redBlueLabel := db.Label{Label: "redBlue",
		IP: redBlueLabelIP}
	allLabels := []db.Label{redLabel, blueLabel, yellowLabel, purpleLabel,
		redBlueLabel}

	redContainerIP := "100.1.1.1"
	blueContainerIP := "100.1.1.2"
	yellowContainerIP := "100.1.1.3"
	purpleContainerIP := "100.1.1.4"
	redContainer := db.Container{IP: redContainerIP,
		Labels: []string{"red", "redBlue"},
	}
	blueContainer := db.Container{IP: blueContainerIP,
		Labels: []string{"blue", "redBlue"},
	}
	yellowContainer := db.Container{IP: yellowContainerIP,
		Labels: []string{"yellow"},
	}
	purpleContainer := db.Container{IP: purpleContainerIP,
		Labels: []string{"purple"},
	}
	allContainers := []db.Container{redContainer, blueContainer, yellowContainer,
		purpleContainer}

	matchFmt := "ip4.src==%s && ip4.dst==%s && " +
		"(%d <= udp.dst <= %d || %[3]d <= tcp.dst <= %[4]d)"
	reverseFmt := "ip4.src==%s && ip4.dst==%s && " +
		"(%d <= udp.src <= %d || %[3]d <= tcp.src <= %[4]d)"
	icmpFmt := "ip4.src==%s && ip4.dst==%s && icmp"

	// No connections should result in no ACLs but the default drop rules.
	checkAcl([]db.Connection{}, []db.Label{}, []db.Container{}, []ovsdb.AclCore{},
		true)

	// Test one connection (with range)
	checkAcl([]db.Connection{
		{From: "red",
			To:      "blue",
			MinPort: 80,
			MaxPort: 81}},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 81),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 81),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 81),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 81),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			}},
		true)

	// Test connecting from label with multiple containers
	checkAcl([]db.Connection{
		{From: "redBlue",
			To:      "yellow",
			MinPort: 80,
			MaxPort: 80}},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					yellowLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					yellowLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, yellowLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, yellowLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, blueContainerIP,
					yellowLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, blueContainerIP,
					yellowLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, yellowLabelIP,
					blueContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, yellowLabelIP,
					blueContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					yellowLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					yellowLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, yellowLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, yellowLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, blueContainerIP,
					yellowLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, blueContainerIP,
					yellowLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, yellowLabelIP,
					blueContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, yellowLabelIP,
					blueContainerIP),
				Action:   "allow",
				Priority: 1,
			}},
		true)

	// Test removing a connection
	checkAcl([]db.Connection{
		{From: "red",
			To:      "blue",
			MinPort: 80,
			MaxPort: 80}},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			}},
		true)
	checkAcl([]db.Connection{},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{},
		false)

	// Test removing one connection, but not another
	checkAcl([]db.Connection{
		{From: "red",
			To:      "blue",
			MinPort: 80,
			MaxPort: 80},
		{From: "yellow",
			To:      "purple",
			MinPort: 80,
			MaxPort: 80}},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, redContainerIP,
					blueLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, blueLabelIP,
					redContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, yellowContainerIP,
					purpleLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, yellowContainerIP,
					purpleLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, purpleLabelIP,
					yellowContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, purpleLabelIP,
					yellowContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, redContainerIP,
					blueLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, blueLabelIP,
					redContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, yellowContainerIP,
					purpleLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, yellowContainerIP,
					purpleLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, purpleLabelIP,
					yellowContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, purpleLabelIP,
					yellowContainerIP),
				Action:   "allow",
				Priority: 1,
			}},
		true)
	checkAcl([]db.Connection{
		{From: "yellow",
			To:      "purple",
			MinPort: 80,
			MaxPort: 80}},
		allLabels,
		allContainers,
		[]ovsdb.AclCore{
			{Direction: "to-lport",
				Match: fmt.Sprintf(matchFmt, yellowContainerIP,
					purpleLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(matchFmt, yellowContainerIP,
					purpleLabelIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(reverseFmt, purpleLabelIP,
					yellowContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(reverseFmt, purpleLabelIP,
					yellowContainerIP, 80, 80),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, yellowContainerIP,
					purpleLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, yellowContainerIP,
					purpleLabelIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "to-lport",
				Match: fmt.Sprintf(icmpFmt, purpleLabelIP,
					yellowContainerIP),
				Action:   "allow",
				Priority: 1,
			},
			{Direction: "from-lport",
				Match: fmt.Sprintf(icmpFmt, purpleLabelIP,
					yellowContainerIP),
				Action:   "allow",
				Priority: 1,
			}},
		true)
}

type ACLList []ovsdb.Acl

func (lst ACLList) Len() int {
	return len(lst)
}

func (lst ACLList) Swap(i, j int) {
	lst[i], lst[j] = lst[j], lst[i]
}

func (lst ACLList) Less(i, j int) bool {
	l, r := lst[i], lst[j]

	switch {
	case l.Core.Match != r.Core.Match:
		return l.Core.Match < r.Core.Match
	case l.Core.Direction != r.Core.Direction:
		return l.Core.Direction < r.Core.Direction
	case l.Core.Action != r.Core.Action:
		return l.Core.Action < r.Core.Action
	default:
		return l.Core.Priority < r.Core.Priority
	}
}

// Because we only use a single switch, this ovsdb mock assumes that all configuration
// changes apply to the same switch.
type fakeOvsdb struct {
	acls []ovsdb.Acl
}

// Unused in the tests.
func (odb *fakeOvsdb) Close() {}

func (odb *fakeOvsdb) CreateSwitch(lswitch string) error {
	return nil
}

func (odb *fakeOvsdb) ListLogicalPorts(lswitch string) ([]ovsdb.LPort, error) {
	return nil, nil
}

func (odb *fakeOvsdb) CreateLogicalPort(lswitch string, lport ovsdb.LPort) error {
	return nil
}

func (odb *fakeOvsdb) DeleteLogicalPort(lswitch string, lport ovsdb.LPort) error {
	return nil
}

func (odb *fakeOvsdb) ListACLs(lswitch string) ([]ovsdb.Acl, error) {
	var result []ovsdb.Acl
	for _, acl := range odb.acls {
		result = append(result, acl)
	}
	return result, nil
}

func (odb *fakeOvsdb) CreateACL(lswitch string, acl ovsdb.Acl) error {
	odb.acls = append(odb.acls, acl)

	return nil
}

func (odb *fakeOvsdb) DeleteACL(lswitch string, acl ovsdb.Acl) error {
	for i := 0; i < len(odb.acls); i++ {
		odbACL := odb.acls[i]
		if acl.Core.Direction != "*" &&
			odbACL.Core.Direction != acl.Core.Direction {
			continue
		}
		if acl.Core.Match != "*" && odbACL.Core.Match != acl.Core.Match {
			continue
		}
		if acl.Core.Priority >= 0 &&
			odbACL.Core.Priority != acl.Core.Priority {
			continue
		}
		odb.acls = append(odb.acls[:i], odb.acls[i+1:]...)
		// Because deleting an element shifts the i+1th element into the ith
		// spot, we need to stay at the same index to not skip the next element.
		i--
	}
	return nil
}

func (odb *fakeOvsdb) GetInterfacesMap() (map[string][]ovsdb.Interface, error) {
	return nil, nil
}

func (odb *fakeOvsdb) CreateInterface(iface ovsdb.Interface) error {
	return nil
}

func (odb *fakeOvsdb) DeleteInterface(iface ovsdb.Interface) error {
	return nil
}

func (odb *fakeOvsdb) ModifyInterface(iface ovsdb.Interface) error {
	return nil
}

func (odb *fakeOvsdb) SetBridgeMac(bridge, mac string) error {
	return nil
}

func (odb *fakeOvsdb) GetOFPortsMap() (map[string]int, error) {
	return nil, nil
}
