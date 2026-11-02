PYTHON ?= python3
GO ?= go

.PHONY: demo controller test test-ha integration build-agent build-native-agent package-agent package-controller check clean

demo:
	$(PYTHON) -m controller --demo --listen 127.0.0.1:8787 --data-dir .local/demo

controller:
	$(PYTHON) -m controller --help

test:
	$(PYTHON) -m unittest discover -s controller/tests -v
	cd agent && $(GO) test ./...
	node --test dashboard/tests/*.test.*

integration: build-native-agent
	SEG_AGENT_BINARY=$(CURDIR)/.local/bin/seg-agent $(PYTHON) -m unittest discover -s tests -v

test-ha:
	$(PYTHON) -c 'import os; assert os.environ.get("SEG_TEST_DATABASE_URL") and os.environ.get("SEG_TEST_TRAFFIC_DATABASE_URL"), "Set both SEG_TEST_* database URLs to isolated prthak_test_ databases"'
	$(PYTHON) -m unittest discover -s tests -p test_ha_integration.py -v

build-native-agent:
	mkdir -p .local/bin
	cd agent && $(GO) build -trimpath -buildvcs=false -o ../.local/bin/seg-agent ./cmd/seg-agent

build-agent:
	mkdir -p agent/bin
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags='-s -w' -o bin/seg-agent-linux-amd64 ./cmd/seg-agent
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags='-s -w' -o bin/seg-agent-linux-arm64 ./cmd/seg-agent

package-agent: build-agent
	$(PYTHON) scripts/package-agent.py

package-controller:
	$(PYTHON) scripts/package-controller.py

check:
	PYTHONPYCACHEPREFIX=$(CURDIR)/.local/pycache $(PYTHON) -m compileall -q controller scripts tests
	node --check dashboard/policy-catalogue-page.js
	node --check dashboard/alerts-catalogue-page.js
	node --check dashboard/account-menu.js
	node --check dashboard/risk-page.js
	node --check dashboard/traffic-catalogue-page.js
	node --check dashboard/audit-catalogue-page.js
	node --check dashboard/source-banks-page.js
	node --check dashboard/app.js
	node --check dashboard/filters.js
	node --check dashboard/topology.js
	node --check dashboard/routing.js
	node --check dashboard/services.js
	node --check dashboard/service-groups-page.js
	node --check dashboard/learning-page.js
	node --check dashboard/hit-monitoring-page.js
	node --check dashboard/recommendations.js
	node --check dashboard/approvals-page.js
	node --check dashboard/recommendations-page.js
	node --check dashboard/platform.js
	node --check dashboard/settings-page.js
	node --check dashboard/settings-ha-page.js
	node --check dashboard/settings-appliance-page.js
	node --check dashboard/settings-certificates-page.js
	node --check dashboard/settings-agents-page.js
	node --check dashboard/settings-notifications-page.js
	node --check dashboard/settings-endpoint-certificates-page.js
	node --check dashboard/settings-recovery-page.js
	node --check dashboard/settings-application-port-page.js
	node --check dashboard/settings-setup-page.js
	node --check dashboard/agent-installation.js
	node --check dashboard/locations.js
	node --check dashboard/locations-page.js
	node --check dashboard/managed.js
	node --check dashboard/managed-page.js
	node --check dashboard/default-deny-page.js
	node --check dashboard/metadata-page.js
	node --check dashboard/firewall.js
	node --check dashboard/firewall-page.js
	node --check dashboard/access-page.js
	node --check dashboard/server-lifecycle-page.js

clean:
	rm -rf agent/bin
