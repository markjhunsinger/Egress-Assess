import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch


def test_sweep_flag_exists():
    """--sweep flag must be recognized without error."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--server',
                            '--username', 'u', '--password', 'p']):
        from common import helpers
        args = helpers.cli_parser()
    assert args.sweep is True


def test_sweep_server_requires_username_password():
    """--sweep --server without credentials must exit."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--server']):
        from common import helpers
        with pytest.raises(SystemExit):
            helpers.cli_parser()


def test_sweep_client_requires_ip_username_password():
    """--sweep --client without --ip must exit."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--client',
                            '--username', 'u', '--password', 'p']):
        from common import helpers
        with pytest.raises(SystemExit):
            helpers.cli_parser()


def test_sweep_client_does_not_require_datatype():
    """--sweep --client must not require --datatype."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--client',
                            '--ip', '1.2.3.4', '--username', 'u', '--password', 'p']):
        from common import helpers
        args = helpers.cli_parser()
    assert args.sweep is True
