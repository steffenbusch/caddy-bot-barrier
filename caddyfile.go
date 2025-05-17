// Copyright 2025 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package botbarrier

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Initialize the module by registering it with Caddy
func init() {
	caddy.RegisterModule(BotBarrier{})
	httpcaddyfile.RegisterHandlerDirective("bot_barrier", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("bot_barrier", "before", "basic_auth")
}

// parseCaddyfile parses the Caddyfile configuration
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m = new(BotBarrier)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UnmarshalCaddyfile parses the configuration from the Caddyfile.
func (bb *BotBarrier) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			param := d.Val()
			var arg string
			if !d.Args(&arg) {
				return d.ArgErr()
			}
			switch param {
			case "secret":
				bb.Secret = arg
			case "complexity":
				bb.Complexity = arg
			case "valid_for":
				duration, err := time.ParseDuration(arg)
				if err != nil {
					return d.Errf("invalid duration: %v", err)
				}
				bb.ValidFor = duration
			case "seed_cookie_name":
				bb.SeedCookieName = arg
			case "solution_cookie_name":
				bb.SolutionCookieName = arg
			case "mac_cookie_name":
				bb.MacCookieName = arg
			case "template":
				bb.TemplatePath = arg
			default:
				return d.Errf("unknown option: %s", param)
			}
		}
	}
	return nil
}
