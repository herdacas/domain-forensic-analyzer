"""Regression coverage for starting with the system Python."""
from pathlib import Path
from unittest.mock import patch

import pytest
import run


def test_main_restarts_with_project_python_before_importing_analyzers():
    project_env = Path(run.__file__).resolve().parent / '.venv'
    env_python = project_env / ('Scripts/python.exe' if run.os.name == 'nt' else 'bin/python')
    with patch.object(run.sys, 'prefix', '/system-python'), \
         patch.object(run.sys, 'argv', ['run.py', 'example.com']), \
         patch.object(Path, 'is_file', return_value=True), \
         patch.object(run.os, 'execv', side_effect=RuntimeError('restart')) as restart:
        with pytest.raises(RuntimeError, match='restart'):
            run.main()
    restart.assert_called_once_with(str(env_python), [str(env_python), str(Path(run.__file__).resolve()), 'example.com'])
