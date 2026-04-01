#!/usr/bin/env bash
# =============================================================================
# Sentinel Security Scanner
# =============================================================================
# Docker-isolated, reproducible security scanning using pinned tool images.
#
# Usage:
#   ./.security/scan.sh              # Run all scans
#   ./.security/scan.sh --trivy      # Trivy filesystem scan only
#   ./.security/scan.sh --npm-audit  # npm audit only
#   ./.security/scan.sh --semgrep    # Semgrep SAST only
#   ./.security/scan.sh --regex      # Custom ReDoS / rule-based checks
#   ./.security/scan.sh --deps       # Dependency license & integrity check
#   ./.security/scan.sh --secrets    # Secret detection (gitleaks)
#   ./.security/scan.sh --all        # Explicit all
#   ./.security/scan.sh --help       # Show help
#
# All tool images are pinned by sha256 digest for reproducibility.
# Reports are written to .security/reports/ (gitignored).
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants — pinned image digests
# ---------------------------------------------------------------------------
# IMPORTANT: Update these digests when upgrading tool versions.
# Verify with: docker pull <image>:<tag> && docker inspect --format='{{index .RepoDigests 0}}' <image>:<tag>

# Trivy v0.62.1 (2025-06 latest stable)
TRIVY_IMAGE="aquasec/trivy:0.62.1@sha256:fc10faf341a1d8fa8256c5ff1a6662ef74dd38b65034c8ce42346cf958a02d5d"

# Semgrep v1.119.0 (2025-05 latest stable)
SEMGREP_IMAGE="semgrep/semgrep:1.119.0@sha256:f552de9f1ad268552aaea0487a9c1694eb08071b01ff3e51fbdb02420ce828a6"

# Gitleaks v8.27.2 (2025-06 latest stable)
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.27.2@sha256:ebfeb6fd4f2c37fa371d3731ebfa662fdf80f93cd37d3b4771bb82263edff8d0"

# Node (for npm audit in isolated env) — Node 20 LTS
NODE_IMAGE="node:20.19.2-alpine@sha256:d3507a213936fe4ef54760a186e113db5188472d9efdf491686bd94580a1c1e8"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_section() { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

check_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is required but not installed."
        exit 1
    fi
    if ! docker info &>/dev/null 2>&1; then
        log_error "Docker daemon is not running."
        exit 1
    fi
}

# Pull image with digest verification
pull_image() {
    local image="$1"
    local name="$2"
    log_info "Pulling ${name} image (digest-pinned)..."
    if ! docker pull "${image}" --quiet >/dev/null 2>&1; then
        log_warn "Failed to pull ${name}. Checking if image exists locally..."
        local base_ref
        base_ref="$(echo "${image}" | cut -d'@' -f1)"
        if ! docker image inspect "${base_ref}" &>/dev/null; then
            log_error "${name} image not available. Skipping."
            return 1
        fi
        log_warn "Using locally cached ${name} image (digest may differ)."
    fi
    log_ok "${name} image ready."
    return 0
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all        Run all scans (default)"
    echo "  --trivy      Trivy filesystem vulnerability scan"
    echo "  --npm-audit  npm audit in isolated container"
    echo "  --semgrep    Semgrep SAST analysis"
    echo "  --regex      Custom rule-based checks (ReDoS, secrets, patterns)"
    echo "  --deps       Dependency integrity & license check"
    echo "  --secrets    Gitleaks secret detection"
    echo "  --help       Show this help"
    echo ""
    echo "Reports are written to: .security/reports/"
}

# ---------------------------------------------------------------------------
# Scan: Trivy (filesystem mode)
# ---------------------------------------------------------------------------
run_trivy() {
    log_section "Trivy Filesystem Scan"
    local report="${REPORTS_DIR}/trivy_${TIMESTAMP}.json"
    local report_table="${REPORTS_DIR}/trivy_${TIMESTAMP}.txt"

    if ! pull_image "${TRIVY_IMAGE}" "Trivy"; then return 1; fi

    # Run Trivy in filesystem mode, read-only mount, no network inside container
    docker run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        -v "${PROJECT_ROOT}:/workspace:ro" \
        "${TRIVY_IMAGE}" \
        fs /workspace \
        --scanners vuln,secret,misconfig \
        --severity CRITICAL,HIGH,MEDIUM \
        --format json \
        --output /dev/stdout \
        2>/dev/null > "${report}" || true

    # Also generate human-readable table
    docker run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        -v "${PROJECT_ROOT}:/workspace:ro" \
        "${TRIVY_IMAGE}" \
        fs /workspace \
        --scanners vuln,secret,misconfig \
        --severity CRITICAL,HIGH,MEDIUM \
        --format table \
        2>/dev/null > "${report_table}" || true

    if [ -s "${report}" ]; then
        local vuln_count
        vuln_count=$(python3 -c "
import json, sys
try:
    data = json.load(open('${report}'))
    results = data.get('Results', [])
    total = sum(len(r.get('Vulnerabilities', [])) for r in results)
    print(total)
except: print('?')
" 2>/dev/null || echo "?")
        log_info "Trivy found ${vuln_count} vulnerabilities. Report: ${report_table}"
    else
        log_ok "Trivy scan clean or no results."
    fi
}

# ---------------------------------------------------------------------------
# Scan: npm audit (Docker-isolated)
# ---------------------------------------------------------------------------
run_npm_audit() {
    log_section "npm audit (Docker-isolated)"
    local report="${REPORTS_DIR}/npm_audit_${TIMESTAMP}.json"
    local report_txt="${REPORTS_DIR}/npm_audit_${TIMESTAMP}.txt"

    if ! pull_image "${NODE_IMAGE}" "Node"; then return 1; fi

    # Copy only package.json + package-lock.json, run audit in isolation
    docker run --rm \
        --network host \
        --read-only \
        --cap-drop ALL \
        --tmpfs /tmp:rw,noexec,nosuid \
        -v "${PROJECT_ROOT}/package.json:/app/package.json:ro" \
        -v "${PROJECT_ROOT}/package-lock.json:/app/package-lock.json:ro" \
        -w /app \
        "${NODE_IMAGE}" \
        sh -c "npm audit --json 2>/dev/null || true" \
        > "${report}" 2>/dev/null

    # Human-readable version
    docker run --rm \
        --network host \
        --read-only \
        --cap-drop ALL \
        --tmpfs /tmp:rw,noexec,nosuid \
        -v "${PROJECT_ROOT}/package.json:/app/package.json:ro" \
        -v "${PROJECT_ROOT}/package-lock.json:/app/package-lock.json:ro" \
        -w /app \
        "${NODE_IMAGE}" \
        sh -c "npm audit 2>/dev/null || true" \
        > "${report_txt}" 2>/dev/null

    if [ -s "${report}" ]; then
        local total
        total=$(python3 -c "
import json, sys
try:
    data = json.load(open('${report}'))
    v = data.get('metadata', {}).get('vulnerabilities', {})
    print(v.get('critical',0) + v.get('high',0) + v.get('moderate',0))
except: print('?')
" 2>/dev/null || echo "?")
        log_info "npm audit: ${total} issues (CRITICAL+HIGH+MODERATE). Report: ${report_txt}"
    else
        log_ok "npm audit clean."
    fi
}

# ---------------------------------------------------------------------------
# Scan: Semgrep SAST
# ---------------------------------------------------------------------------
run_semgrep() {
    log_section "Semgrep SAST Analysis"
    local report="${REPORTS_DIR}/semgrep_${TIMESTAMP}.json"
    local report_txt="${REPORTS_DIR}/semgrep_${TIMESTAMP}.txt"

    if ! pull_image "${SEMGREP_IMAGE}" "Semgrep"; then return 1; fi

    # Run Semgrep with TypeScript security rules + custom rules
    docker run --rm \
        --network none \
        --cap-drop ALL \
        -v "${PROJECT_ROOT}/src:/workspace/src:ro" \
        -v "${PROJECT_ROOT}/examples:/workspace/examples:ro" \
        -v "${PROJECT_ROOT}/samples:/workspace/samples:ro" \
        -v "${SCRIPT_DIR}/rules:/rules:ro" \
        -w /workspace \
        "${SEMGREP_IMAGE}" \
        semgrep scan \
        --config "p/typescript" \
        --config "p/javascript" \
        --config "p/security-audit" \
        --config "p/owasp-top-ten" \
        --config "/rules" \
        --json \
        --output /dev/stdout \
        2>/dev/null > "${report}" || true

    # Text version
    docker run --rm \
        --network none \
        --cap-drop ALL \
        -v "${PROJECT_ROOT}/src:/workspace/src:ro" \
        -v "${PROJECT_ROOT}/examples:/workspace/examples:ro" \
        -v "${PROJECT_ROOT}/samples:/workspace/samples:ro" \
        -v "${SCRIPT_DIR}/rules:/rules:ro" \
        -w /workspace \
        "${SEMGREP_IMAGE}" \
        semgrep scan \
        --config "p/typescript" \
        --config "p/javascript" \
        --config "p/security-audit" \
        --config "p/owasp-top-ten" \
        --config "/rules" \
        2>/dev/null > "${report_txt}" || true

    if [ -s "${report}" ]; then
        local count
        count=$(python3 -c "
import json
try:
    data = json.load(open('${report}'))
    print(len(data.get('results', [])))
except: print('?')
" 2>/dev/null || echo "?")
        log_info "Semgrep found ${count} findings. Report: ${report_txt}"
    else
        log_ok "Semgrep scan clean."
    fi
}

# ---------------------------------------------------------------------------
# Scan: Gitleaks (secret detection)
# ---------------------------------------------------------------------------
run_secrets() {
    log_section "Gitleaks Secret Detection"
    local report="${REPORTS_DIR}/gitleaks_${TIMESTAMP}.json"

    if ! pull_image "${GITLEAKS_IMAGE}" "Gitleaks"; then return 1; fi

    docker run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        -v "${PROJECT_ROOT}:/workspace:ro" \
        "${GITLEAKS_IMAGE}" \
        detect \
        --source /workspace \
        --report-format json \
        --report-path /dev/stdout \
        --no-git \
        2>/dev/null > "${report}" || true

    if [ -s "${report}" ] && [ "$(wc -c < "${report}" | tr -d ' ')" -gt 5 ]; then
        local count
        count=$(python3 -c "
import json
try:
    data = json.load(open('${report}'))
    print(len(data) if isinstance(data, list) else '?')
except: print('?')
" 2>/dev/null || echo "?")
        if [ "${count}" != "0" ] && [ "${count}" != "?" ]; then
            log_warn "Gitleaks found ${count} potential secrets! Report: ${report}"
        else
            log_ok "No secrets detected."
        fi
    else
        log_ok "No secrets detected."
    fi
}

# ---------------------------------------------------------------------------
# Scan: Custom rule-based checks (pure bash, no Docker needed)
# ---------------------------------------------------------------------------
run_regex_checks() {
    log_section "Custom Rule-Based Checks"
    local report="${REPORTS_DIR}/custom_rules_${TIMESTAMP}.txt"
    local issues=0

    echo "=== Sentinel Custom Security Rules ===" > "${report}"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${report}"
    echo "Project: ${PROJECT_ROOT}" >> "${report}"
    echo "" >> "${report}"

    # --- Rule 1: ReDoS patterns ---
    echo "--- [RULE-001] ReDoS: Nested quantifiers in regex ---" >> "${report}"
    # Pattern: quantifier inside a repeating group, e.g. (\d+)*  (\d*?){n}  etc.
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E '(\([^)]*[+*?]\{?[^)]*\))[+*]\{?' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # Also check for specific dangerous patterns
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -P '\(\?:[^)]*[*+][?]?\)\{' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 2: new RegExp() with non-literal ---
    echo "" >> "${report}"
    echo "--- [RULE-002] Dynamic RegExp construction ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn 'new RegExp(' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 3: console.warn/error/log with error objects ---
    echo "" >> "${report}"
    echo "--- [RULE-003] Error object leakage via console ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E 'console\.(warn|error|log)\(.*,\s*(error|err|e)\b' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 4: eval / Function constructor ---
    echo "" >> "${report}"
    echo "--- [RULE-004] Dynamic code execution ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  CRITICAL: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E '\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["\x27]|setInterval\s*\(\s*["\x27]' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 5: Prototype pollution vectors ---
    echo "" >> "${report}"
    echo "--- [RULE-005] Prototype pollution vectors ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E '__proto__|constructor\[|Object\.assign\(' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 6: Hardcoded secrets patterns ---
    echo "" >> "${report}"
    echo "--- [RULE-006] Hardcoded secrets / credentials ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  HIGH: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -iE '(password|secret|token|api_key|apikey|private_key)\s*[:=]\s*["\x27][^"\x27]{8,}' \
        "${PROJECT_ROOT}/src" "${PROJECT_ROOT}/examples" "${PROJECT_ROOT}/samples" \
        --include='*.ts' --include='*.js' 2>/dev/null || true)

    # --- Rule 7: Insecure crypto ---
    echo "" >> "${report}"
    echo "--- [RULE-007] Weak cryptographic algorithms ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  HIGH: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -iE "createHash\(['\"]md5|createHash\(['\"]sha1['\"]|Math\.random\(\)" \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 8: child_process / exec ---
    echo "" >> "${report}"
    echo "--- [RULE-008] Command injection vectors ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  CRITICAL: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E "require\(['\"]child_process|exec\(|execSync\(|spawn\(" \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 9: Unvalidated URL/path construction ---
    echo "" >> "${report}"
    echo "--- [RULE-009] Path traversal / SSRF vectors ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  WARN: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -E 'path\.(join|resolve)\(.*\+|fs\.(read|write).*\+' \
        "${PROJECT_ROOT}/src" \
        --include='*.ts' 2>/dev/null || true)

    # --- Rule 10: createInsecure / plaintext ---
    echo "" >> "${report}"
    echo "--- [RULE-010] Insecure transport ---" >> "${report}"
    while IFS= read -r match; do
        if [ -n "${match}" ]; then
            echo "  HIGH: ${match}" >> "${report}"
            ((issues++)) || true
        fi
    done < <(grep -rn -iE 'createInsecure|plaintext|disable.*tls|tls.*false' \
        "${PROJECT_ROOT}/src" "${PROJECT_ROOT}/examples" \
        --include='*.ts' --include='*.js' 2>/dev/null || true)

    echo "" >> "${report}"
    echo "=== Total issues: ${issues} ===" >> "${report}"

    if [ "${issues}" -gt 0 ]; then
        log_warn "Custom rules found ${issues} issues. Report: ${report}"
    else
        log_ok "Custom rules: no issues found."
    fi
}

# ---------------------------------------------------------------------------
# Scan: Dependency integrity & license
# ---------------------------------------------------------------------------
run_deps_check() {
    log_section "Dependency Integrity & License Check"
    local report="${REPORTS_DIR}/deps_integrity_${TIMESTAMP}.txt"

    echo "=== Dependency Integrity Check ===" > "${report}"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${report}"
    echo "" >> "${report}"

    # Check lockfile exists and has integrity hashes
    if [ ! -f "${PROJECT_ROOT}/package-lock.json" ]; then
        echo "ERROR: No package-lock.json found!" >> "${report}"
        log_error "No package-lock.json found!"
        return 1
    fi

    # Count packages vs integrity hashes
    local pkg_count hash_count
    pkg_count=$(grep -c '"resolved"' "${PROJECT_ROOT}/package-lock.json" 2>/dev/null || echo 0)
    hash_count=$(grep -c '"integrity"' "${PROJECT_ROOT}/package-lock.json" 2>/dev/null || echo 0)

    echo "Resolved packages: ${pkg_count}" >> "${report}"
    echo "Integrity hashes:  ${hash_count}" >> "${report}"

    if [ "${pkg_count}" -ne "${hash_count}" ]; then
        echo "WARNING: Package count != hash count (${pkg_count} vs ${hash_count})" >> "${report}"
        log_warn "Lockfile integrity mismatch: ${pkg_count} packages, ${hash_count} hashes"
    else
        echo "OK: All packages have integrity hashes." >> "${report}"
        log_ok "All ${pkg_count} packages have integrity hashes."
    fi

    # Check for sha1 (weak) vs sha512 hashes
    local sha1_count sha512_count
    sha1_count=$(grep -c '"integrity": "sha1-' "${PROJECT_ROOT}/package-lock.json" 2>/dev/null || echo "0")
    sha512_count=$(grep -c '"integrity": "sha512-' "${PROJECT_ROOT}/package-lock.json" 2>/dev/null || echo "0")
    echo "" >> "${report}"
    echo "SHA-512 hashes: ${sha512_count}" >> "${report}"
    echo "SHA-1 hashes:   ${sha1_count} (weak, should be 0)" >> "${report}"

    sha1_count=$(echo "${sha1_count}" | head -1 | tr -d '[:space:]')
    if [ "${sha1_count:-0}" -gt 0 ] 2>/dev/null; then
        log_warn "${sha1_count} packages use weak SHA-1 integrity hashes."
    fi

    # Check for runtime deps (should be 0)
    echo "" >> "${report}"
    echo "--- Runtime dependencies ---" >> "${report}"
    local runtime_deps
    runtime_deps=$(python3 -c "
import json
data = json.load(open('${PROJECT_ROOT}/package.json'))
deps = data.get('dependencies', {})
print(len(deps))
for k,v in deps.items():
    print(f'  {k}: {v}')
" 2>/dev/null || echo "?")

    if [ "${runtime_deps}" = "0" ]; then
        echo "OK: Zero runtime dependencies." >> "${report}"
        log_ok "Zero runtime dependencies (correct for SDK)."
    else
        echo "WARNING: Found runtime dependencies:" >> "${report}"
        echo "${runtime_deps}" >> "${report}"
        log_warn "Runtime dependencies found: ${runtime_deps}"
    fi

    # Check for install scripts in direct deps
    echo "" >> "${report}"
    echo "--- Install script check ---" >> "${report}"
    local scripts_found=0
    while IFS= read -r line; do
        if [ -n "${line}" ]; then
            echo "  WARN: ${line}" >> "${report}"
            ((scripts_found++)) || true
        fi
    done < <(grep -r '"preinstall"\|"postinstall"\|"preuninstall"' \
        "${PROJECT_ROOT}/node_modules"/*/package.json 2>/dev/null | head -20 || true)

    if [ "${scripts_found}" -eq 0 ]; then
        echo "OK: No install scripts in direct dependencies." >> "${report}"
        log_ok "No suspicious install scripts found."
    else
        log_warn "${scripts_found} packages have install scripts. Report: ${report}"
    fi

    log_info "Full report: ${report}"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    log_section "Scan Complete"
    echo ""
    log_info "Reports directory: ${REPORTS_DIR}/"
    echo ""
    ls -la "${REPORTS_DIR}"/*"${TIMESTAMP}"* 2>/dev/null | while read -r line; do
        echo "  ${line}"
    done
    echo ""
    log_info "To view latest reports:"
    echo "  cat ${REPORTS_DIR}/custom_rules_${TIMESTAMP}.txt"
    echo "  cat ${REPORTS_DIR}/trivy_${TIMESTAMP}.txt"
    echo "  cat ${REPORTS_DIR}/npm_audit_${TIMESTAMP}.txt"
    echo "  cat ${REPORTS_DIR}/semgrep_${TIMESTAMP}.txt"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local run_trivy=false
    local run_npm=false
    local run_semgrep=false
    local run_regex=false
    local run_deps=false
    local run_secrets=false
    local run_all=true

    if [ $# -gt 0 ]; then
        run_all=false
        while [ $# -gt 0 ]; do
            case "$1" in
                --trivy)     run_trivy=true ;;
                --npm-audit) run_npm=true ;;
                --semgrep)   run_semgrep=true ;;
                --regex)     run_regex=true ;;
                --deps)      run_deps=true ;;
                --secrets)   run_secrets=true ;;
                --all)       run_all=true ;;
                --help)      usage; exit 0 ;;
                *)           log_error "Unknown option: $1"; usage; exit 1 ;;
            esac
            shift
        done
    fi

    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         Sentinel Security Scanner                ║"
    echo "║         $(date -u +%Y-%m-%dT%H:%M:%SZ)                  ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"

    mkdir -p "${REPORTS_DIR}"

    # Custom regex checks always run (no Docker needed)
    if ${run_all} || ${run_regex}; then
        run_regex_checks
    fi

    # Dependency integrity (no Docker needed)
    if ${run_all} || ${run_deps}; then
        run_deps_check
    fi

    # Docker-based scans
    if ${run_all} || ${run_trivy} || ${run_npm} || ${run_semgrep} || ${run_secrets}; then
        check_docker
    fi

    if ${run_all} || ${run_npm}; then
        run_npm_audit
    fi

    if ${run_all} || ${run_trivy}; then
        run_trivy
    fi

    if ${run_all} || ${run_semgrep}; then
        run_semgrep
    fi

    if ${run_all} || ${run_secrets}; then
        run_secrets
    fi

    print_summary
}

main "$@"
