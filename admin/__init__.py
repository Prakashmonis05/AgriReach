from flask import Blueprint

admin_bp = Blueprint(
    'admin',
    __name__,
    template_folder='templates',   # 🔥 REQUIRED
    url_prefix='/admin'
)

from . import routes
