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


def test_sweep_rejects_data_size():
    """--sweep with --data-size must exit."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--server',
                            '--username', 'u', '--password', 'p',
                            '--data-size', '5']):
        import importlib
        from common import helpers
        importlib.reload(helpers)
        with pytest.raises(SystemExit):
            helpers.cli_parser()


def test_sweep_client_does_not_require_datatype():
    """--sweep --client must not require --datatype."""
    with patch('sys.argv', ['Egress-Assess.py', '--sweep', '--client',
                            '--ip', '1.2.3.4', '--username', 'u', '--password', 'p']):
        from common import helpers
        args = helpers.cli_parser()
    assert args.sweep is True


import socket
from unittest.mock import patch, MagicMock


def test_check_port_available_when_free():
    from common.helpers import check_port_available
    assert check_port_available(19999) is True


def test_check_port_available_when_bound():
    from common.helpers import check_port_available
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 19998))
    try:
        assert check_port_available(19998) is False
    finally:
        s.close()


def test_preflight_server_sweep_detects_missing_cert(tmp_path):
    from common.helpers import preflight_server_sweep
    mock_server = MagicMock()
    mock_server.protocol = 'https'
    mock_server.port = 18443
    with patch('common.helpers.ea_path', return_value=str(tmp_path)):
        errors = preflight_server_sweep([mock_server])
    assert any('server.pem' in e for e in errors)


def test_preflight_server_sweep_detects_blocked_port(tmp_path):
    from common.helpers import preflight_server_sweep
    (tmp_path / 'server.pem').write_text('fake')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 19997))
    mock_server = MagicMock()
    mock_server.protocol = 'http'
    mock_server.port = 19997
    try:
        with patch('common.helpers.ea_path', return_value=str(tmp_path)):
            errors = preflight_server_sweep([mock_server])
        assert any('19997' in e for e in errors)
    finally:
        s.close()


def test_preflight_server_sweep_skips_icmp(tmp_path):
    from common.helpers import preflight_server_sweep
    (tmp_path / 'server.pem').write_text('fake')
    mock_server = MagicMock(spec=['protocol'])  # no .port attribute
    mock_server.protocol = 'icmp'
    with patch('common.helpers.ea_path', return_value=str(tmp_path)):
        errors = preflight_server_sweep([mock_server])
    assert errors == []
