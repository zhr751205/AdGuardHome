package home

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/dhcpd"

	"github.com/stretchr/testify/assert"
)

func TestClients(t *testing.T) {
	clients := clientsContainer{}
	clients.testing = true

	clients.Init(nil, nil, nil)

	t.Run("add_success", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"1.1.1.1", "1:2:3::4", "aa:aa:aa:aa:aa:aa"},
			Name: "client1",
		}

		ok, err := clients.Add(c)
		assert.True(t, ok)
		assert.Nil(t, err)

		c = &Client{
			IDs:  []string{"2.2.2.2"},
			Name: "client2",
		}

		ok, err = clients.Add(c)
		assert.True(t, ok)
		assert.Nil(t, err)

		c, ok = clients.Find("1.1.1.1")
		assert.True(t, ok)
		assert.Equal(t, "client1", c.Name)

		c, ok = clients.Find("1:2:3::4")
		assert.True(t, ok)
		assert.Equal(t, "client1", c.Name)

		c, ok = clients.Find("2.2.2.2")
		assert.True(t, ok)
		assert.Equal(t, "client2", c.Name)

		assert.True(t, !clients.Exists("1.2.3.4", ClientSourceHostsFile))
		assert.True(t, clients.Exists("1.1.1.1", ClientSourceHostsFile))
		assert.True(t, clients.Exists("2.2.2.2", ClientSourceHostsFile))
	})

	t.Run("add_fail_name", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"1.2.3.5"},
			Name: "client1",
		}

		ok, err := clients.Add(c)
		assert.False(t, ok)
		assert.Nil(t, err)
	})

	t.Run("add_fail_ip", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"2.2.2.2"},
			Name: "client3",
		}

		ok, err := clients.Add(c)
		assert.False(t, ok)
		assert.NotNil(t, err)
	})

	t.Run("update_fail_name", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"1.2.3.0"},
			Name: "client3",
		}

		err := clients.Update("client3", c)
		assert.NotNil(t, err)

		c = &Client{
			IDs:  []string{"1.2.3.0"},
			Name: "client2",
		}

		err = clients.Update("client3", c)
		assert.NotNil(t, err)
	})

	t.Run("update_fail_ip", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"2.2.2.2"},
			Name: "client1",
		}

		err := clients.Update("client1", c)
		assert.NotNil(t, err)
	})

	t.Run("update_success", func(t *testing.T) {
		c := &Client{
			IDs:  []string{"1.1.1.2"},
			Name: "client1",
		}

		err := clients.Update("client1", c)
		assert.Nil(t, err)

		assert.True(t, !clients.Exists("1.1.1.1", ClientSourceHostsFile))
		assert.True(t, clients.Exists("1.1.1.2", ClientSourceHostsFile))

		c = &Client{
			IDs:            []string{"1.1.1.2"},
			Name:           "client1-renamed",
			UseOwnSettings: true,
		}

		err = clients.Update("client1", c)
		assert.Nil(t, err)

		c, ok := clients.Find("1.1.1.2")
		assert.True(t, ok)
		assert.Equal(t, "client1-renamed", c.Name)
		assert.True(t, c.UseOwnSettings)
		assert.Nil(t, clients.list["client1"])
		if assert.Len(t, c.IDs, 1) {
			assert.Equal(t, "1.1.1.2", c.IDs[0])
		}
	})

	t.Run("del_success", func(t *testing.T) {
		ok := clients.Del("client1-renamed")
		assert.True(t, ok)
		assert.False(t, clients.Exists("1.1.1.2", ClientSourceHostsFile))
	})

	t.Run("del_fail", func(t *testing.T) {
		ok := clients.Del("client3")
		assert.False(t, ok)
	})

	t.Run("addhost_success", func(t *testing.T) {
		ok, err := clients.AddHost("1.1.1.1", "host", ClientSourceARP)
		assert.True(t, ok)
		assert.Nil(t, err)

		ok, err = clients.AddHost("1.1.1.1", "host2", ClientSourceARP)
		assert.True(t, ok)
		assert.Nil(t, err)

		ok, err = clients.AddHost("1.1.1.1", "host3", ClientSourceHostsFile)
		assert.True(t, ok)
		assert.Nil(t, err)

		assert.True(t, clients.Exists("1.1.1.1", ClientSourceHostsFile))
	})

	t.Run("addhost_fail", func(t *testing.T) {
		ok, err := clients.AddHost("1.1.1.1", "host1", ClientSourceRDNS)
		assert.False(t, ok)
		assert.Nil(t, err)
	})
}

func TestClientsWhois(t *testing.T) {
	var c *Client
	clients := clientsContainer{}
	clients.testing = true
	clients.Init(nil, nil, nil)

	whois := [][]string{{"orgname", "orgname-val"}, {"country", "country-val"}}
	// set whois info on new client
	clients.SetWhoisInfo("1.1.1.255", whois)
	if assert.NotNil(t, clients.ipHost["1.1.1.255"]) {
		h := clients.ipHost["1.1.1.255"]
		if assert.Len(t, h.WhoisInfo, 2) && assert.Len(t, h.WhoisInfo[0], 2) {
			assert.Equal(t, "orgname-val", h.WhoisInfo[0][1])
		}
	}

	// set whois info on existing auto-client
	_, _ = clients.AddHost("1.1.1.1", "host", ClientSourceRDNS)
	clients.SetWhoisInfo("1.1.1.1", whois)
	if assert.NotNil(t, clients.ipHost["1.1.1.1"]) {
		h := clients.ipHost["1.1.1.1"]
		if assert.Len(t, h.WhoisInfo, 2) && assert.Len(t, h.WhoisInfo[0], 2) {
			assert.Equal(t, "orgname-val", h.WhoisInfo[0][1])
		}
	}

	// Check that we cannot set whois info on a manually-added client
	c = &Client{
		IDs:  []string{"1.1.1.2"},
		Name: "client1",
	}
	_, _ = clients.Add(c)
	clients.SetWhoisInfo("1.1.1.2", whois)
	assert.Nil(t, clients.ipHost["1.1.1.2"])
	_ = clients.Del("client1")
}

func TestClientsAddExisting(t *testing.T) {
	var c *Client
	clients := clientsContainer{}
	clients.testing = true
	clients.Init(nil, nil, nil)

	// some test variables
	mac, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	testIP := "1.2.3.4"

	// add a client
	c = &Client{
		IDs:  []string{"1.1.1.1", "1:2:3::4", "aa:aa:aa:aa:aa:aa", "2.2.2.0/24"},
		Name: "client1",
	}
	ok, err := clients.Add(c)
	assert.True(t, ok)
	assert.Nil(t, err)

	// add an auto-client with the same IP - it's allowed
	ok, err = clients.AddHost("1.1.1.1", "test", ClientSourceRDNS)
	assert.True(t, ok)
	assert.Nil(t, err)

	// now some more complicated stuff
	// first, init a DHCP server with a single static lease
	config := dhcpd.ServerConfig{
		DBFilePath: "leases.db",
	}
	defer func() { _ = os.Remove("leases.db") }()
	clients.dhcpServer = dhcpd.Create(config)
	err = clients.dhcpServer.AddStaticLease(dhcpd.Lease{
		HWAddr:   mac,
		IP:       net.ParseIP(testIP).To4(),
		Hostname: "testhost",
		Expiry:   time.Now().Add(time.Hour),
	})
	assert.Nil(t, err)

	// add a new client with the same IP as for a client with MAC
	c = &Client{
		IDs:  []string{testIP},
		Name: "client2",
	}
	ok, err = clients.Add(c)
	assert.True(t, ok)
	assert.Nil(t, err)

	// add a new client with the IP from the client1's IP range
	c = &Client{
		IDs:  []string{"2.2.2.2"},
		Name: "client3",
	}
	ok, err = clients.Add(c)
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestClientsCustomUpstream(t *testing.T) {
	clients := clientsContainer{}
	clients.testing = true

	clients.Init(nil, nil, nil)

	// add client with upstreams
	c := &Client{
		IDs:  []string{"1.1.1.1", "1:2:3::4", "aa:aa:aa:aa:aa:aa"},
		Name: "client1",
		Upstreams: []string{
			"1.1.1.1",
			"[/example.org/]8.8.8.8",
		},
	}
	ok, err := clients.Add(c)
	assert.Nil(t, err)
	assert.True(t, ok)

	config := clients.FindUpstreams("1.2.3.4")
	assert.Nil(t, config)

	config = clients.FindUpstreams("1.1.1.1")
	assert.NotNil(t, config)
	assert.Equal(t, 1, len(config.Upstreams))
	assert.Equal(t, 1, len(config.DomainReservedUpstreams))
}

func TestProcessHost(t *testing.T) {
	const (
		name int = iota
		host
		want

		fieldsNum
	)

	testCases := [][fieldsNum]string{{
		name: "valid",
		host: "abc",
		want: "abc",
	}, {
		name: "with_trailing_zero_byte",
		host: "abc\x00",
		want: "abc",
	}}

	for _, tc := range testCases {
		t.Run(tc[name], func(t *testing.T) {
			assert.Equal(t, tc[want], sanitizeHost(tc[host]))
		})
	}
}
