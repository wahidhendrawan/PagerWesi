from __future__ import annotations

from cloud.core import Finding, Severity, Status

try:
    from kubernetes import client, config
    _HAS_K8S = True
except ImportError:
    client = None  # type: ignore[assignment]
    config = None  # type: ignore[assignment]
    _HAS_K8S = False

CONTROL_IDS = {
    "K8S-NET-001",
    "K8S-RBAC-001",
    "K8S-POD-001",
    "K8S-SEC-001",
}


def _selected(args, control_id: str) -> bool:
    return not args.control or control_id in args.control


def _finding(control_id, title, status, severity, resource, evidence, remediation=""):
    return Finding(
        control_id, title, status, severity, resource, evidence, remediation
    )


def _check_network_policies(v1: client.CoreV1Api, net: client.NetworkingV1Api):
    """K8S-NET-001: Every namespace has at least one NetworkPolicy."""
    namespaces = v1.list_namespace().items
    policies = net.list_network_policy_for_all_namespaces().items
    ns_with_policy = {p.metadata.namespace for p in policies}
    missing = [
        ns.metadata.name for ns in namespaces
        if ns.metadata.name not in ns_with_policy
        and not ns.metadata.name.startswith("kube-")
    ]
    return _finding(
        "K8S-NET-001",
        "Every namespace has at least one NetworkPolicy",
        Status.FAIL if missing else Status.PASS,
        Severity.HIGH,
        "cluster/namespaces",
        f"missing_policy={','.join(missing) or 'none'}",
        "Create a default-deny NetworkPolicy in each namespace.",
    )


def _check_cluster_admin_bindings(rbac: client.RbacAuthorizationV1Api):
    """K8S-RBAC-001: No cluster-admin bindings to non-system SAs."""
    bindings = rbac.list_cluster_role_binding().items
    violations = []
    for b in bindings:
        if (
            b.role_ref.name == "cluster-admin"
            and b.subjects
        ):
            for s in b.subjects:
                if (
                    s.kind == "ServiceAccount"
                    and not (s.namespace or "").startswith("kube-")
                ):
                    violations.append(
                        f"{s.namespace}/{s.name}@{b.metadata.name}"
                    )
    return _finding(
        "K8S-RBAC-001",
        "No cluster-admin bindings to non-system ServiceAccounts",
        Status.FAIL if violations else Status.PASS,
        Severity.CRITICAL,
        "cluster/clusterrolebindings",
        f"violations={','.join(violations) or 'none'}",
        "Remove cluster-admin ClusterRoleBindings for non-system SAs.",
    )


def _check_privileged_pods(v1: client.CoreV1Api):
    """K8S-POD-001: No pods running as privileged."""
    pods = v1.list_pod_for_all_namespaces().items
    privileged = []
    for pod in pods:
        if pod.metadata.namespace.startswith("kube-"):
            continue
        for c in pod.spec.containers or []:
            sc = c.security_context
            if sc and sc.privileged:
                privileged.append(
                    f"{pod.metadata.namespace}/{pod.metadata.name}/{c.name}"
                )
    return _finding(
        "K8S-POD-001",
        "No pods running as privileged",
        Status.FAIL if privileged else Status.PASS,
        Severity.CRITICAL,
        "cluster/pods",
        f"privileged={','.join(privileged) or 'none'}",
        "Remove privileged flag from container securityContext.",
    )


def _check_pod_security_standards(v1: client.CoreV1Api):
    """K8S-SEC-001: Pod Security Standards enforcement."""
    namespaces = v1.list_namespace().items
    PSS_LABEL = "pod-security.kubernetes.io/enforce"
    unenforced = [
        ns.metadata.name for ns in namespaces
        if not ns.metadata.name.startswith("kube-")
        and PSS_LABEL not in (ns.metadata.labels or {})
    ]
    return _finding(
        "K8S-SEC-001",
        "Pod Security Standards enforcement is configured",
        Status.FAIL if unenforced else Status.PASS,
        Severity.HIGH,
        "cluster/namespaces",
        f"unenforced={','.join(unenforced) or 'none'}",
        "Add pod-security.kubernetes.io/enforce label to namespaces.",
    )


def _annotate_plan(findings: list[Finding]) -> list[Finding]:
    annotated = []
    for f in findings:
        if f.status == Status.FAIL:
            annotated.append(Finding(
                f.control_id, f.title, f.status, f.severity,
                f.resource, f.evidence, f.remediation, f.benchmark,
                planned=True,
                before={"compliant": False, "evidence": f.evidence},
                after={"compliant": True, "recommendation": f.remediation},
            ))
        else:
            annotated.append(f)
    return annotated


def run_audit(args) -> list[Finding]:
    if not _HAS_K8S:
        return [_finding(
            "K8S-NET-001",
            "Kubernetes client library available",
            Status.ERROR, Severity.HIGH, "k8s:cluster",
            "ImportError: pip install kubernetes",
            "Install kubernetes package: pip install kubernetes",
        )]

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    v1 = client.CoreV1Api()
    net = client.NetworkingV1Api()
    rbac = client.RbacAuthorizationV1Api()
    findings: list[Finding] = []

    checks = {
        "K8S-NET-001": lambda: _check_network_policies(v1, net),
        "K8S-RBAC-001": lambda: _check_cluster_admin_bindings(rbac),
        "K8S-POD-001": lambda: _check_privileged_pods(v1),
        "K8S-SEC-001": lambda: _check_pod_security_standards(v1),
    }

    for control_id, check_fn in checks.items():
        if _selected(args, control_id):
            try:
                findings.append(check_fn())
            except Exception as exc:
                findings.append(_finding(
                    control_id,
                    f"{control_id} check failed",
                    Status.ERROR, Severity.HIGH,
                    "k8s:cluster",
                    f"{type(exc).__name__}: {exc}",
                ))

    if getattr(args, "mode", "audit") == "plan":
        findings = _annotate_plan(findings)
    return findings
