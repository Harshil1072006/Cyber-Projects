import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(__file__))
from provision import Provisioner

def test_provisioner_validation_failure(tmp_path):
    prov = Provisioner("dev", str(tmp_path / "non_existent"))
    assert prov.validate() == False

def test_provisioner_validation_success(tmp_path):
    prov = Provisioner("dev", str(tmp_path))
    assert prov.validate() == True

@patch("subprocess.run")
def test_provisioner_run_plan(mock_run, tmp_path):
    prov = Provisioner("dev", str(tmp_path))
    prov.run_terraform("plan")
    
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[0] == "terraform"
    assert args[1] == "plan"
    assert args[2] == "-var"
    assert args[3] == "environment=dev"

@patch("subprocess.run")
def test_provisioner_run_apply(mock_run, tmp_path):
    prov = Provisioner("prod", str(tmp_path))
    prov.run_terraform("apply")
    
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args[0] == "terraform"
    assert args[1] == "apply"
    assert "-auto-approve" in args

@patch("subprocess.run")
def test_provisioner_run_failure(mock_run, tmp_path):
    mock_run.side_effect = subprocess.CalledProcessError(1, "terraform", stderr="Error occurred")
    prov = Provisioner("prod", str(tmp_path))
    success = prov.run_terraform("apply")
    assert success == False
