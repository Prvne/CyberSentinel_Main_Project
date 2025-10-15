import odoorpc
import os
class OdooConnector:
    def __init__(self, host='localhost', port=8069, timeout=10):
        self.host = host
        self.port = port
    def _connect(self, db, user=None, password=None):
        # NOTE: in Phase1 we assume a local sandbox with known credentials
        odoo = odoorpc.ODOO(self.host, port=self.port, timeout=10)
        u = user or os.getenv('ODOO_USER', 'admin')
        p = password or os.getenv('ODOO_PASSWORD', 'admin')
        odoo.login(db, u, p)
        return odoo
    def list_users(self, db_name=None):
        if not db_name:
            raise ValueError("Please pass a db_name for sandbox")
        odoo = self._connect(db_name)
        users = odoo.env['res.users'].search_read([], ['id','login','name'], limit=200)
        return users
