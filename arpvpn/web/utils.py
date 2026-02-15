from datetime import datetime
from typing import Any

import faker
from flask import templating

from arpvpn.__version__ import commit, release
from arpvpn.common.properties import global_properties
from arpvpn.web.static.assets.resources import APP_NAME, APP_REPOSITORY_URL, APP_LICENSE_URL

fake = faker.Faker()


def render_template(template_path: str, **variables: Any):
    context = {
        "app_name": APP_NAME,
        "app_repository_url": APP_REPOSITORY_URL,
        "app_license_url": APP_LICENSE_URL,
        "year": datetime.now().strftime("%Y"),
        "version_info": {"release": release, "commit": commit},
        "dev_env": global_properties.dev_env
    }
    if variables:
        context.update(variables)
    return templating.render_template(template_path, **context)
