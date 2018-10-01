// Copyright 2017 CNI authors
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

// This is the Source Based Routing plugin that sets up source based routing.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

// PluginConf is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type PluginConf struct {
	types.NetConf // You may wish to not nest this type

	// This is the previous result, when called in the context of a chained
	// plugin. Because this plugin supports multiple versions, we'll have to
	// parse this in two passes. If your plugin is not chained, this can be
	// removed (though you may wish to error if a non-chainable plugin is
	// chained).
	// If you need to modify the result before returning it, you will need
	// to actually convert it to a concrete versioned struct.
	RawPrevResult *map[string]interface{} `json:"prevResult"`
	PrevResult    *current.Result         `json:"-"`

	// Add plugin-specific flags here
	LogFile           string `json:"logfile"`
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}
	// End previous result parsing

	if conf.LogFile != "" {
		file, err := os.OpenFile(conf.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}

		log.SetOutput(file)
	}

	return &conf, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("This plugin must be called as chained plugin")
	}

	// We do a single interface name, stored in args.IfName
	log.Printf("Working with interface: %s", args.IfName)

	// Get list of IP addresses on that interface
	if len(conf.PrevResult.IPs) == 0 {
		// No IP addresses; that makes no sense. Pack it in.
		return fmt.Errorf("No IP addresses on interface: %s", args.IfName)
	}

	// ips contains the IPConfig structures that were passed, filtered somewhat
	ips := make([]*current.IPConfig, 0, len(conf.PrevResult.IPs))

	for _, ip := range conf.PrevResult.IPs {
		// IPs have an interface that is an index into the interfaces array.
		if ip.Interface == nil {
			log.Printf("No interface for IP address %s", ip.Address.IP)
			continue
		}

		// Skip all IPs we know belong to an interface with the wrong name.
		intIdx := *ip.Interface
		if intIdx >= 0 && intIdx < len(conf.PrevResult.Interfaces) && conf.PrevResult.Interfaces[intIdx].Name != args.IfName {
			log.Printf("Incorrect interface for IP address %s", ip.Address.IP)
			continue
		}

		log.Printf("Found IP address %s", ip.Address.IP.String())
		ips = append(ips, ip)
	}

	nsname := os.Getenv("CNI_NETNS")
	log.Printf("Network namespace to use: %s", nsname)
	namespace, err := ns.GetNS(nsname)
	if err != nil {
		return fmt.Errorf("Network namespace does not exist: %v", err)
	}

	log.Printf("Previous result supplied: %v", conf.PrevResult)
	err = namespace.Do(func(_ ns.NetNS) error {
		return doRoutes(ips, conf.PrevResult.Routes, args.IfName)
	})

	// Pass through the result for the next plugin
	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}


func doRoutes (ips []*current.IPConfig, origRoutes []*types.Route, iface string) error {

	// Pick a table ID to use. We pick the first table ID from 100 on that has
	// no existing rules mapping to it and no existing routes in it.
	rules, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Failed to list all rules: %v", err)
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Failed to list all routes: %v", err)
	}

	table := 100
	for {
		found := false
		for _, rule := range rules {
			if rule.Table == table {
				found = true
				break
			}
		}

		for _, route := range routes {
			if route.Table == table {
				found = true
				break
			}
		}

		if found {
			table++
		} else {
			break
		}
	}

	log.Printf("First unreferenced table: %d", table)

    link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Cannot find network interface %s: %v", iface, err)
	}

	linkIndex := link.Attrs().Index

	// Loop through setting up source based rules and default routes.
	for _, ip := range ips {
		log.Printf("Set rule for source %s", ip.String())
		rule := netlink.NewRule()
		rule.Table = table
		rule.Src = &ip.Address

		if err = netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("Failed to add rule: %v", err)
		}

		// Add a default route, since this was removed by multus.
		if ip.Gateway != nil {
			log.Printf("Adding default route to gateway %s", ip.Gateway.String())

			var dest net.IPNet
			if ip.Version == "4" {
				dest.IP = net.IPv4zero
				dest.Mask = net.CIDRMask(0, 32)
			} else {
				dest.IP = net.IPv6zero
				dest.Mask = net.CIDRMask(0, 64)
			}

			route := netlink.Route{
				Dst: &dest,
				Gw: ip.Gateway,
				Table: table,
				LinkIndex: linkIndex }

			err = netlink.RouteAdd(&route)
			if err != nil {
				return fmt.Errorf("Failed to add default route to %s: %v",
					ip.Gateway.String(),
					err)
			}
		}
	}

	// Move all routes into the correct table. We are taking a shortcut; all
	// the routes have been added to the interface anyway but in the wrong
	// table, so instead of removing them we just move them to the table we
	// want them in.
	routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Unable to list routes: %v", err)
	}

	for _, route := range routes {
		if route.Dst == nil {
			// Should be no such rules; give up.
			continue
		}

		log.Printf("Moving route %s from table %d to %d",
			route.Dst.String(), route.Table, table)

		err := netlink.RouteDel(&route)
		if err != nil {
			return fmt.Errorf("Failed to delete route: %v", err)
		}

		route.Table = table

		err = netlink.RouteAdd(&route)
		if err != nil {
			return fmt.Errorf("Failed to readd route: %v", err)
		}
	}

	return nil
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	_ = conf

	// Do your delete here

	return nil
}

func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdGet, cmdDel, version.All, "TODO")
}

func cmdGet(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}
