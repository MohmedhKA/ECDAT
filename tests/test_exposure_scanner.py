import pytest
from pathlib import Path
from ecdat.models import ExposureProfile
from ecdat.exposure_scanner.k8s_parser import scan_k8s_manifests
from ecdat.exposure_scanner.docker_parser import scan_docker_compose

def test_k8s_manifest_exposure_classification(tmp_path):
    k8s_yaml = """
apiVersion: v1
kind: Service
metadata:
  name: payment-gateway
spec:
  type: LoadBalancer
  ports:
    - port: 443
---
apiVersion: v1
kind: Service
metadata:
  name: internal-redis
spec:
  type: ClusterIP
  ports:
    - port: 6379
"""
    manifest_file = tmp_path / "k8s-services.yaml"
    manifest_file.write_text(k8s_yaml, encoding="utf-8")

    results = scan_k8s_manifests(tmp_path)
    assert "payment-gateway" in results
    profile, p_hndl, prov = results["payment-gateway"]
    assert profile == ExposureProfile.PUBLIC
    assert p_hndl == 1.0

    assert "internal-redis" in results
    profile_r, p_hndl_r, _ = results["internal-redis"]
    assert profile_r == ExposureProfile.INTERNAL
    assert p_hndl_r == 0.05

def test_docker_compose_exposure_classification(tmp_path):
    compose_yaml = """
version: '3.8'
services:
  web-api:
    image: myapp/api
    ports:
      - "8080:8080"
  db:
    image: postgres:15
    ports:
      - "127.0.0.1:5432:5432"
  worker:
    image: myapp/worker
"""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(compose_yaml, encoding="utf-8")

    results = scan_docker_compose(tmp_path)
    assert "web-api" in results
    prof_w, p_hndl_w, _ = results["web-api"]
    assert prof_w == ExposureProfile.PUBLIC
    assert p_hndl_w == 1.0

    assert "db" in results
    prof_d, p_hndl_d, _ = results["db"]
    assert prof_d == ExposureProfile.INTERNAL
    assert p_hndl_d == 0.20

    assert "worker" in results
    prof_k, p_hndl_k, _ = results["worker"]
    assert prof_k == ExposureProfile.INTERNAL
    assert p_hndl_k == 0.01
