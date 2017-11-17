package session_modules

import (
	"fmt"
	"github.com/evilsocket/bettercap/net"
	"github.com/evilsocket/bettercap/session"
	"time"
)

type Discovery struct {
	session.SessionModule

	refresh int
	before  net.ArpTable
	current net.ArpTable
	quit    chan bool
}

func NewDiscovery(s *session.Session) *Discovery {
	d := &Discovery{
		SessionModule: session.NewSessionModule(s),

		refresh: 1,
		before:  nil,
		current: nil,
		quit:    make(chan bool),
	}

	d.AddHandler(session.NewModuleHandler("net.recon (on|off)", "^net\\.recon\\s+(on|off)$",
		"Start/stop network hosts discovery in background.",
		func(args []string) error {
			if args[0] == "on" {
				return d.Start()
			} else {
				return d.Stop()
			}
		}))

	d.AddHandler(session.NewModuleHandler("net.show", "^net\\.show$",
		"Show current hosts list.",
		func(args []string) error {
			return d.Show()
		}))

	return d
}

func (d Discovery) Name() string {
	return "Network Recon"
}

func (d Discovery) Description() string {
	return "Read periodically the ARP cache in order to monitor for new hosts on the network."
}

func (d Discovery) Author() string {
	return "Simone Margaritelli <evilsocket@protonmail.com>"
}

func (d Discovery) OnSessionEnded(s *session.Session) {
	if d.Running() {
		d.Stop()
	}
}

func (d *Discovery) Start() error {
	if d.Running() == false {
		d.SetRunning(true)

		go func() {
			log.Info("Network discovery started.\n")

			for {
				select {
				case <-time.After(time.Duration(d.refresh) * time.Second):
					var err error

					if d.current, err = net.ArpUpdate(d.Session.Interface.Name()); err != nil {
						log.Error(err)
						continue
					}

					var new net.ArpTable = make(net.ArpTable)
					var rem net.ArpTable = make(net.ArpTable)

					if d.before != nil {
						new = net.ArpDiff(d.current, d.before)
						rem = net.ArpDiff(d.before, d.current)
					} else {
						new = d.current
					}

					if len(new) > 0 || len(rem) > 0 {
						n_gw_shared := 0
						for ip, mac := range new {
							if ip != d.Session.Gateway.IpAddress && mac == d.Session.Gateway.HwAddress {
								n_gw_shared++
							}
						}

						if n_gw_shared > 0 {
							log.Warningf("WARNING: %d endpoints share the same MAC of the gateway, there're might be some IP isolation going on.\n", n_gw_shared)
						}

						// refresh target pool
						for ip, mac := range new {
							d.Session.Targets.AddIfNotExist(ip, mac)
						}

						for ip, mac := range rem {
							d.Session.Targets.Remove(ip, mac)
						}
					}

					d.before = d.current

				case <-d.quit:
					log.Info("Network discovery stopped.\n")
					return
				}
			}
		}()

		return nil
	} else {
		return fmt.Errorf("Network discovery already started.")
	}
}

func (d *Discovery) Show() error {
	d.Session.Targets.Dump()
	return nil
}

func (d *Discovery) Stop() error {
	if d.Running() == true {
		d.SetRunning(false)
		d.quit <- true
		return nil
	} else {
		return fmt.Errorf("Network discovery already stopped.")
	}
}
