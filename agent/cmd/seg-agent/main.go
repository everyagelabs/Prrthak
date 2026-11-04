package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"example.com/microseg/agent/internal/agent"
)

func main() {
	rollbackJournal := flag.String("rollback-journal", "", "independent managed rollback journal (systemd watchdog only)")
	rollbackNonce := flag.String("rollback-nonce", "", "managed rollback generation")
	configPath := flag.String("config", "/etc/seg-agent/config.json", "JSON configuration path")
	once := flag.Bool("once", false, "run one discovery/policy-sync cycle; no traffic collection")
	simulate := flag.Bool("simulate", false, "use synthetic discovery and never invoke firewall commands; loopback demo controller only")
	hostname := flag.String("simulate-hostname", "simulated-rhel-01", "hostname for simulated discovery")
	version := flag.Bool("version", false, "print agent version")
	recoverCertificate := flag.String("recover-certificate", "", "recover endpoint identity with a private one-time token file; never changes firewall rules")
	check := flag.Bool("check-config", false, "validate configuration, CA and private enrollment credentials without networking or mutation")
	checkUpgrade := flag.Bool("check-upgrade", false, "refuse binary replacement while an enforcement/rollback transaction is active; no mutations")
	installCheck := flag.Bool("install-check", false, "also validate canonical paths supported by the stock systemd service (with --check-config)")
	checkRoot := flag.String("check-root", "", "staging filesystem root for --check-config; no service starts")
	checkCA := flag.String("check-ca", "", "source CA artifact override for installer preflight (with --check-config)")
	checkEndpointCA := flag.String("check-endpoint-ca", "", "source endpoint issuing CA override for installer preflight (with --check-config)")
	installationLeaseFD := flag.Int("installation-lease-fd", -1, "inherited canonical native installer lease (preflight only)")
	checkToken := flag.String("check-token-file", "", "private token file override for installer preflight (with --check-config)")
	statusFlag := flag.Bool("status", false, "show persisted automatic enrollment/controller readiness; exit2 while pending")
	scanNow := flag.Bool("scan-now", false, "request immediate service discovery from the running agent; no new enrollment")
	prepareStart := flag.Bool("prepare-start", false, "reset readiness generation before a systemd restart; no controller or firewall request")
	prepareSetup := flag.String("prepare-setup", "", "validate a private GUI setup file and prepare fixed data files; no network or firewall operations")
	setupOutput := flag.String("setup-output", "", "empty owned 0700 output directory for --prepare-setup")
	prepareHost := flag.String("prepare-host", "", "explicit GUI setup file for protected OS dependency preparation and private UFW assessment")
	prepareFamily := flag.String("prepare-family", "", "native OS package family for --prepare-host (rhel or ubuntu)")
	installDependencies := flag.Bool("install-dependencies", false, "explicit local dependency-install consent for the automatic --prepare-host installer")
	applyConfiguration := flag.String("apply-configuration", "", "apply an independently approved private endpoint configuration kit locally")
	rollbackConfiguration := flag.String("rollback-configuration", "", "independent systemd configuration rollback journal")
	checkConfiguration := flag.String("check-configuration", "", "read-only signature and exact local-config check for a private endpoint configuration kit")
	configurationState := flag.Bool("configuration-state", false, "print public current configuration receipt; no credentials or networking")
	checkRelease := flag.Bool("check-release", false, "verify signed candidate runtime bytes without installation or networking")
	releaseManifest := flag.String("release-manifest", "", "signed public runtime integrity manifest")
	releaseTrust := flag.String("release-trust", "", "independently established public release signer trust")
	releaseBinary := flag.String("release-binary", "", "candidate agent binary path")
	releaseUnit := flag.String("release-unit", "", "candidate systemd unit path")
	rollbackNetworkControl := flag.String("rollback-network-control", "", "independent owned network-control rollback journal")
	expireQuarantine := flag.String("expire-quarantine", "", "independent original-deadline quarantine expiry journal")
	networkControlNonce := flag.String("network-control-nonce", "", "owned network-control journal generation")
	restoreQuarantine := flag.String("restore-quarantine", "", "boot reconciliation of the remaining original quarantine lease")
	flag.Parse()
	if *rollbackNetworkControl != "" || *expireQuarantine != "" || *networkControlNonce != "" || *restoreQuarantine != "" {
		invalid := flag.NArg() != 0
		modes := 0
		for _, value := range []string{*rollbackNetworkControl, *expireQuarantine, *restoreQuarantine} {
			if value != "" {
				modes++
			}
		}
		if modes != 1 || (*restoreQuarantine != "" && *networkControlNonce != "") || (*restoreQuarantine == "" && *networkControlNonce == "") {
			invalid = true
		}
		flag.Visit(func(value *flag.Flag) {
			if value.Name != "rollback-network-control" && value.Name != "expire-quarantine" && value.Name != "network-control-nonce" && value.Name != "restore-quarantine" {
				invalid = true
			}
		})
		if invalid {
			log.Fatal("independent network rollback/expiry/boot recovery cannot be combined with another mode and needs its exact nonce")
		}
		var err error
		switch {
		case *restoreQuarantine != "":
			err = agent.RestoreQuarantine(*restoreQuarantine, agent.ExecRunner{})
		case *expireQuarantine != "":
			err = agent.ExpireQuarantine(*expireQuarantine, *networkControlNonce, agent.ExecRunner{})
		default:
			err = agent.RollbackNetworkControl(*rollbackNetworkControl, *networkControlNonce, agent.ExecRunner{})
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	dependencyConsentSelected := false
	flag.Visit(func(value *flag.Flag) {
		if value.Name == "install-dependencies" {
			dependencyConsentSelected = true
		}
	})
	if *installationLeaseFD != -1 && (*installationLeaseFD < 3 || !*check && !*checkUpgrade || *checkRoot != "") {
		log.Fatal("installation lease descriptor is supported only by canonical native installer preflight")
	}
	if *prepareHost != "" || *prepareFamily != "" || dependencyConsentSelected {
		invalid := flag.NArg() != 0 || *prepareHost == "" || (*prepareFamily != "rhel" && *prepareFamily != "ubuntu") || *releaseManifest == "" || *releaseTrust == "" || *releaseBinary == "" || *releaseUnit == ""
		flag.Visit(func(value *flag.Flag) {
			switch value.Name {
			case "prepare-host", "prepare-family", "install-dependencies", "release-manifest", "release-trust", "release-binary", "release-unit":
			default:
				invalid = true
			}
		})
		if invalid {
			log.Fatal("host preparation requires only its explicit setup, family and signed runtime files")
		}
		signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stopSignals()
		ctx, cancel := context.WithTimeout(signalCtx, 35*time.Minute)
		defer cancel()
		if err := agent.PrepareHostFromSetupWithDependencies(ctx, *prepareHost, *prepareFamily, *releaseManifest, *releaseTrust, *releaseBinary, *releaseUnit, *installDependencies); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Explicit host preparation complete; UFW and firewall service activation remain unchanged. Private assessment metadata is reported after enrollment.")
		return
	}
	if *checkRelease {
		invalid := flag.NArg() != 0 || *releaseManifest == "" || *releaseTrust == "" || *releaseBinary == "" || *releaseUnit == ""
		flag.Visit(func(value *flag.Flag) {
			switch value.Name {
			case "check-release", "release-manifest", "release-trust", "release-binary", "release-unit":
			default:
				invalid = true
			}
		})
		if invalid {
			log.Fatal("release verification requires only its exact fixed candidate files")
		}
		if err := agent.VerifyReleaseFiles(*releaseManifest, *releaseTrust, *releaseBinary, *releaseUnit); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Trusted Ed25519 runtime signature and exact agent/service bytes verified")
		return
	}
	if *releaseManifest != "" || *releaseTrust != "" || *releaseBinary != "" || *releaseUnit != "" {
		log.Fatal("release file options require --check-release")
	}
	if *checkConfiguration != "" || *configurationState {
		invalid := flag.NArg() != 0 || *checkConfiguration != "" && *configurationState
		flag.Visit(func(value *flag.Flag) {
			if value.Name != "check-configuration" && value.Name != "configuration-state" && value.Name != "config" {
				invalid = true
			}
		})
		if invalid {
			log.Fatal("read-only endpoint configuration cannot be combined with another mode")
		}
		if *checkConfiguration != "" {
			if err := agent.CheckEndpointConfiguration(*checkConfiguration, *configPath); err != nil {
				log.Fatal(err)
			}
			fmt.Println("Configuration signature and local binding verified; native identity/network/systemd acceptance remains separate")
			return
		}
		state, err := agent.EndpointConfigurationReceipt(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(state); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *applyConfiguration != "" || *rollbackConfiguration != "" {
		invalid := flag.NArg() != 0 || *applyConfiguration != "" && *rollbackConfiguration != ""
		flag.Visit(func(value *flag.Flag) {
			if value.Name != "apply-configuration" && value.Name != "rollback-configuration" && value.Name != "config" {
				invalid = true
			}
		})
		if invalid {
			log.Fatal("endpoint configuration cannot be combined with another operating mode")
		}
		if *rollbackConfiguration != "" {
			if err := agent.RollbackEndpointConfiguration(*rollbackConfiguration, agent.ExecRunner{}); err != nil {
				if errors.Is(err, agent.ErrStaleConfigurationReview) {
					log.Print(err)
					os.Exit(3)
				}
				log.Fatal(err)
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := agent.ApplyEndpointConfiguration(ctx, *applyConfiguration, *configPath, agent.ExecRunner{}); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Approved endpoint configuration committed after a fresh authenticated report; identity and signing trust preserved")
		return
	}
	if *prepareSetup != "" || *setupOutput != "" {
		if *prepareSetup == "" || *setupOutput == "" {
			log.Fatal("prepare-setup and setup-output are required together")
		}
		invalid := false
		flag.Visit(func(value *flag.Flag) {
			if value.Name != "prepare-setup" && value.Name != "setup-output" {
				invalid = true
			}
		})
		if invalid || flag.NArg() != 0 {
			log.Fatal("private setup preparation cannot be combined with another operating mode")
		}
		host, err := os.Hostname()
		if err != nil {
			log.Fatal("cannot establish this endpoint hostname")
		}
		if err = agent.PrepareSetupFile(*prepareSetup, *setupOutput, host, time.Now().UTC()); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Private endpoint setup prepared; no enrollment or firewall changes were performed")
		return
	}
	if *rollbackJournal != "" || *rollbackNonce != "" {
		if *simulate || *once || *check || *checkUpgrade || *statusFlag || *scanNow || *prepareStart || *version {
			log.Fatal("independent rollback cannot be combined with another operating mode")
		}
		if *rollbackJournal == "" || *rollbackNonce == "" {
			log.Fatal("rollback journal and nonce are required together")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := agent.RunManagedWatchdog(ctx, *rollbackJournal, *rollbackNonce, agent.ExecRunner{}); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *version {
		fmt.Println("Prṛthak (पृथक्) agent " + agent.Version + " (managed enforcement requires explicit local opt-in and approved rollback-protected rollout)")
		return
	}
	c, e := agent.LoadConfig(*configPath, *simulate)
	if e != nil {
		log.Fatal(e)
	}
	if *checkUpgrade {
		if *simulate || *once || *check || *statusFlag || *scanNow || *prepareStart || *recoverCertificate != "" || *checkCA != "" || *checkEndpointCA != "" || *checkToken != "" {
			log.Fatal("check-upgrade cannot be combined with another operating mode")
		}
		if *checkRoot != "" && (!filepath.IsAbs(*checkRoot) || filepath.Clean(*checkRoot) == "/") {
			log.Fatal("check-root must be an absolute staging directory")
		}
		if *installationLeaseFD >= 0 {
			e = agent.CheckInstallerUpgradeSafety(c, *installationLeaseFD)
		} else {
			e = agent.CheckEnforcementUpgradeSafety(agent.RootedConfig(c, *checkRoot))
		}
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println("Agent binary replacement safety checked; no pending enforcement transaction")
		return
	}
	if *recoverCertificate != "" {
		if *simulate || *once || *check || *statusFlag || *scanNow || *prepareStart || *checkEndpointCA != "" {
			log.Fatal("certificate recovery cannot be combined with another operating mode")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if e = agent.RecoverCertificate(ctx, c, *recoverCertificate); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Endpoint certificate recovered with a fresh key; the running agent reloads it on its next sync")
		return
	}
	if *scanNow {
		if *prepareStart || *check || *statusFlag || *once || *installCheck || *checkRoot != "" || *checkCA != "" || *checkEndpointCA != "" || *checkToken != "" {
			log.Fatal("scan-now cannot be combined with other operating modes")
		}
		if e = agent.RequestDiscovery(c); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Prṛthak (पृथक्): service discovery requested; the running agent will scan and report automatically")
		return
	}
	if *prepareStart {
		if *check || *statusFlag || *simulate || *once || *installCheck || *checkRoot != "" || *checkCA != "" || *checkEndpointCA != "" || *checkToken != "" {
			log.Fatal("prepare-start cannot be combined with other operating modes")
		}
		if _, e = agent.PrepareReadiness(c); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Prṛthak (पृथक्) readiness reset for a new service instance")
		return
	}
	if *check {
		if *simulate {
			log.Fatal("installation preflight requires real HTTPS configuration")
		}
		if *installCheck {
			if e = agent.ValidateInstallConfig(c); e != nil {
				log.Fatal(e)
			}
		}
		if *checkRoot != "" && (!filepath.IsAbs(*checkRoot) || filepath.Clean(*checkRoot) == "/") {
			log.Fatal("check-root must be an absolute staging directory")
		}
		validated := agent.RootedConfig(c, *checkRoot)
		if *installCheck || *installationLeaseFD >= 0 {
			if *installationLeaseFD >= 0 {
				e = agent.CheckInstallerUpgradeSafety(c, *installationLeaseFD)
			} else {
				e = agent.CheckEnforcementUpgradeSafety(validated)
			}
			if e != nil {
				log.Fatal(e)
			}
		}
		if *checkCA != "" {
			validated.CACert = *checkCA
		}
		if *checkEndpointCA != "" {
			if c.EndpointCACert != "/etc/seg-agent/endpoint-ca.crt" {
				log.Fatal("endpoint CA override requires the canonical configured endpoint-ca.crt path")
			}
			validated.EndpointCACert = *checkEndpointCA
		}
		if *checkToken != "" {
			validated.EnrollmentTokenFile = *checkToken
			_ = os.Setenv("SEG_ENROLLMENT_TOKEN_FILE", *checkToken)
			if _, err := agent.EnrollmentToken(validated); err != nil {
				log.Fatal(err)
			}
		}
		enrolled, err := agent.CheckBootstrap(validated)
		if err != nil {
			log.Fatal(err)
		}
		if enrolled {
			fmt.Println("Prṛthak (पृथक्) configuration validated: existing mTLS identity ready")
		} else {
			fmt.Println("Prṛthak (पृथक्) configuration validated: HTTPS CA and private enrollment credential ready")
		}
		return
	}
	if *installCheck || *checkRoot != "" || *checkCA != "" || *checkEndpointCA != "" || *checkToken != "" {
		log.Fatal("installer preflight options require --check-config")
	}
	if *statusFlag {
		status, err := agent.ReadReadyStatus(c)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("Prṛthak (पृथक्) registration pending; the systemd agent will enroll and report automatically")
				os.Exit(2)
			}
			log.Fatal(err)
		}
		ready, reason := agent.ReadyStatusMatches(c, status, time.Now())
		if ready {
			fmt.Printf("Prṛthak (पृथक्) ready: server %s (%s) registered and reported to the dashboard\n", status.ServerID, status.Hostname)
			return
		}
		fmt.Printf("Prṛthak (पृथक्) pending: %s; automatic enrollment/sync retries remain active", reason)
		if status.Error != "" {
			fmt.Printf("; %s", status.Error)
		}
		fmt.Println()
		os.Exit(2)
	}
	if *simulate && c.DemoAgentID == "" {
		c.DemoAgentID = os.Getenv("SEG_DEMO_AGENT_ID")
		if c.DemoAgentID == "" {
			c.DemoAgentID = "simulated-rhel-01"
		}
	}
	if !*simulate {
		if e = agent.VerifyInstalledRuntime(); e != nil {
			log.Fatal(e)
		}
	}
	if !*simulate {
		if e = agent.RecoverEndpointConfiguration(*configPath); e != nil {
			log.Fatal(e)
		}
		c, e = agent.LoadConfig(*configPath, false)
		if e != nil {
			log.Fatal(e)
		}
	}
	a, e := agent.New(c, *simulate, *hostname)
	if e != nil {
		log.Fatal(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("Prṛthak (पृथक्) agent %s starting: managed enforcement opt-in=%t, temporary collector enabled by assignment", agent.Version, c.Enforce)
	if e = a.Run(ctx, *once); e != nil {
		log.Fatal(e)
	}
}
