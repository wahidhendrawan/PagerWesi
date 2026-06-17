from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import cloud.k8s_harden as k8s_mod
from cloud.core import Status


def _ns(name, labels=None):
    ns = MagicMock()
    ns.metadata.name = name
    ns.metadata.labels = labels or {}
    return ns


def _pod(ns, name, privileged=False):
    pod = MagicMock()
    pod.metadata.namespace = ns
    pod.metadata.name = name
    c = MagicMock()
    c.name = "main"
    c.security_context = MagicMock(privileged=privileged)
    pod.spec.containers = [c]
    return pod


def _netpol(ns):
    p = MagicMock()
    p.metadata.namespace = ns
    return p


def _setup(mock_client, namespaces, pods, netpols, bindings):
    v1 = mock_client.CoreV1Api.return_value
    v1.list_namespace.return_value.items = namespaces
    v1.list_pod_for_all_namespaces.return_value.items = pods
    net = mock_client.NetworkingV1Api.return_value
    net.list_network_policy_for_all_namespaces.return_value.items = netpols
    rbac = mock_client.RbacAuthorizationV1Api.return_value
    rbac.list_cluster_role_binding.return_value.items = bindings


def _run(mock_client, mode="audit", **setup_kwargs):
    mock_config = MagicMock()
    mock_config.ConfigException = Exception
    _setup(mock_client, **setup_kwargs)
    with (
        patch.object(k8s_mod, "_HAS_K8S", True),
        patch.object(k8s_mod, "config", mock_config),
        patch.object(k8s_mod, "client", mock_client),
    ):
        return k8s_mod.run_audit(SimpleNamespace(control=[], mode=mode))


def test_k8s_all_pass():
    mock_client = MagicMock()
    pss = {"pod-security.kubernetes.io/enforce": "restricted"}
    findings = _run(
        mock_client,
        namespaces=[_ns("default", pss)],
        pods=[],
        netpols=[_netpol("default")],
        bindings=[],
    )
    assert all(f.status == Status.PASS for f in findings)
    assert len(findings) == 4


def test_k8s_privileged_pod_fails():
    mock_client = MagicMock()
    pss = {"pod-security.kubernetes.io/enforce": "baseline"}
    findings = _run(
        mock_client,
        namespaces=[_ns("app", pss)],
        pods=[_pod("app", "bad-pod", privileged=True)],
        netpols=[_netpol("app")],
        bindings=[],
    )
    pod_f = next(f for f in findings if f.control_id == "K8S-POD-001")
    assert pod_f.status == Status.FAIL


def test_k8s_plan_mode_annotates():
    mock_client = MagicMock()
    findings = _run(
        mock_client,
        mode="plan",
        namespaces=[_ns("default")],
        pods=[],
        netpols=[],
        bindings=[],
    )
    planned = [f for f in findings if f.planned]
    assert len(planned) > 0


def test_k8s_missing_library():
    with patch.object(k8s_mod, "_HAS_K8S", False):
        findings = k8s_mod.run_audit(
            SimpleNamespace(control=[], mode="audit")
        )
    assert findings[0].status == Status.ERROR
