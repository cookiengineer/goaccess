package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cookiengineer/goaccess/scanner"
	"github.com/cookiengineer/goaccess/types"

	// Trigger exploit registration via init()
	_ "github.com/cookiengineer/goaccess/exploits"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	arguments := os.Args[2:]

	switch command {
	case "identify":
		runIdentify(arguments)
	case "scan":
		runScan(arguments)
	case "access":
		runAccess(arguments)
	case "list":
		runList(arguments)
	case "completion":
		if len(arguments) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: goaccess completion <bash|zsh>")
			os.Exit(1)
		}
		generateCompletion(arguments[0])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func generateCompletion(shell string) {
	switch shell {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell: %s (use bash or zsh)\n", shell)
		os.Exit(1)
	}
}

const bashCompletion = `# goaccess bash completion
_goaccess() {
    local cur prev words cword
    _init_completion || return

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "identify scan access list completion" -- "$cur"))
        return
    fi

    local cmd="${words[1]}"
    case "$cmd" in
        identify)
            case "$prev" in
                --output|--threads|--timeout)
                    COMPREPLY=()
                    ;;
                *)
                    COMPREPLY=($(compgen -W "--json --output --oui-only --verbose --threads --timeout" -- "$cur"))
                    ;;
            esac
            ;;
        scan)
            case "$prev" in
                --vendor)
                    local vendors
                    vendors=$(goaccess list vendors 2>/dev/null || echo "")
                    COMPREPLY=($(compgen -W "$vendors" -- "$cur"))
                    ;;
                --type)
                    COMPREPLY=($(compgen -W "router camera misc generic" -- "$cur"))
                    ;;
                --output|--threads|--timeout)
                    COMPREPLY=()
                    ;;
                *)
                    COMPREPLY=($(compgen -W "--vendor --type --threads --timeout --skip-creds --skip-exploits --json --output --verbose" -- "$cur"))
                    ;;
            esac
            ;;
        access)
            case "$prev" in
                --payload)
                    COMPREPLY=($(compgen -W "arm arm64 mips mipsle mips64 x86 x86_64" -- "$cur"))
                    ;;
                --output|--threads|--timeout|--listen)
                    COMPREPLY=()
                    ;;
                *)
                    COMPREPLY=($(compgen -W "--threads --timeout --payload --listen --shell --no-exploit --no-creds --json --output --verbose" -- "$cur"))
                    ;;
            esac
            ;;
        list)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "exploits credentials payloads keys vendors" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "--vendor --type --json" -- "$cur"))
            fi
            ;;
        completion)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "bash zsh" -- "$cur"))
            fi
            ;;
    esac
}
complete -F _goaccess goaccess
`

const zshCompletion = `#compdef goaccess

_goaccess() {
    local -a commands
    commands=(
        'identify:Fingerprint target hardware'
        'scan:Scan for vulnerabilities'
        'access:Active exploitation and access'
        'list:List exploits, creds, payloads, keys, vendors'
        'completion:Generate shell completion'
    )

    local state line
    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            local cmd="${line[1]}"
            case "$cmd" in
                identify)
                    _arguments \
                        '--json[Output as JSON]' \
                        '--output[Write JSON output to file]:file:_files' \
                        '--oui-only[Only show OUI vendor lookup]' \
                        '--verbose[Verbose output]' \
                        '--threads[Number of parallel threads]:threads:' \
                        '--timeout[Timeout in seconds]:seconds:' \
                        ':target:_hosts'
                    ;;
                scan)
                    _arguments \
                        '--vendor[Filter exploits by vendor]:vendor:' \
                        '--type[Filter by device type]:type:(router camera misc generic)' \
                        '--threads[Number of parallel threads]:threads:' \
                        '--timeout[Timeout in seconds]:seconds:' \
                        '--skip-creds[Skip credential checks]' \
                        '--skip-exploits[Skip exploit checks]' \
                        '--json[Output as JSON]' \
                        '--output[Write JSON output to file]:file:_files' \
                        '--verbose[Verbose output]' \
                        ':target:_hosts'
                    ;;
                access)
                    _arguments \
                        '--threads[Number of parallel threads]:threads:' \
                        '--timeout[Timeout in seconds]:seconds:' \
                        '--payload[Preferred payload architecture]:arch:(arm arm64 mips mipsle mips64 x86 x86_64)' \
                        '--listen[Listen port for reverse shells]:port:' \
                        '--shell[Drop to interactive shell]' \
                        '--no-exploit[Skip exploitation]' \
                        '--no-creds[Skip credential checks]' \
                        '--json[Output as JSON]' \
                        '--output[Write JSON output to file]:file:_files' \
                        '--verbose[Verbose output]' \
                        ':target:_hosts'
                    ;;
                list)
                    _arguments \
                        '1:resource:(exploits credentials payloads keys vendors)' \
                        '--vendor[Filter by vendor]:vendor:' \
                        '--type[Filter by device type]:type:(router camera misc generic)' \
                        '--json[Output as JSON]'
                    ;;
                completion)
                    _arguments \
                        '1:shell:(bash zsh)'
                    ;;
            esac
            ;;
    esac
}

_goaccess "$@"
`

func printUsage() {
	fmt.Println("GoAccess — IoT Exploitation Framework")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  goaccess identify <target>            Fingerprint target hardware")
	fmt.Println("  goaccess scan <target>                Scan for vulnerabilities")
	fmt.Println("  goaccess access <target>              Active exploitation & access")
	fmt.Println("  goaccess list <resource>              List exploits, creds, payloads, keys")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  goaccess identify 192.168.1.1")
	fmt.Println("  goaccess scan 192.168.1.1 --threads 32")
	fmt.Println("  goaccess access 192.168.1.1 --payload arm")
	fmt.Println("  goaccess list exploits --vendor dlink")
}

func defaultConfig(target string) *types.ScanConfig {
	return &types.ScanConfig{
		Target:  target,
		Threads: 8,
		Timeout: 8 * time.Second,
	}
}

func defaultScanner(config *types.ScanConfig) *scanner.Scanner {
	return scanner.NewScanner(config)
}
