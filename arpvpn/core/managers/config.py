import os
from logging import info, warning, error

import yaml

from arpvpn.common.models.user import UserDict, users
from arpvpn.common.models.tenant import TenantDict, InvitationDict, tenants, invitations
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.logs import log_exception
from arpvpn.common.utils.system import try_makedir
from arpvpn.core.config.logger import config as logger_config
from arpvpn.core.config.traffic import config as traffic_config
from arpvpn.core.config.web import config as web_config
from arpvpn.core.config.wireguard import config as wireguard_config
from arpvpn.web.static.assets.resources import APP_NAME


class ConfigManager:

    CONFIG_FILENAME = f"{APP_NAME.lower()}.yaml"

    def __init__(self):
        self.config_filepath = None

    def load(self):
        try:
            self.config_filepath = global_properties.join_workdir(self.CONFIG_FILENAME)
            self.__load_config__()
            self.save(apply=False)
        except Exception as e:
            log_exception(e, is_fatal=True)
            exit(1)

    @staticmethod
    def load_defaults():
        logger_config.load_defaults()
        web_config.load_defaults()
        wireguard_config.load_defaults()
        traffic_config.load_defaults()

    def __load_config__(self):
        info(f"Restoring configuration from {self.config_filepath}...")
        if not os.path.exists(self.config_filepath):
            warning(f"Unable to restore configuration file {self.config_filepath}: not found.")
            info("Using default configuration...")
            return
        with open(self.config_filepath, "r") as file:
            config = list(yaml.safe_load_all(file))[0]
        if "logger" in config:
            logger_config.load(config["logger"])
            logger_config.apply()
        if "web" in config:
            web_config.load(config["web"])
            web_config.apply()
        if os.path.exists(web_config.credentials_file) and os.path.getsize(web_config.credentials_file) > 0:
            try:
                credentials = UserDict.load(web_config.credentials_file, web_config.secret_key)
                users.set_contents(credentials)
            except Exception:
                error(f"Invalid credentials file detected: {web_config.credentials_file}")
                raise
        else:
            users.clear()
        if os.path.exists(web_config.tenants_file) and os.path.getsize(web_config.tenants_file) > 0:
            try:
                saved_tenants = TenantDict.load(web_config.tenants_file, web_config.secret_key)
                tenants.set_contents(saved_tenants)
            except Exception:
                error(f"Invalid tenants file detected: {web_config.tenants_file}")
                raise
        else:
            tenants.clear()
        if os.path.exists(web_config.invitations_file) and os.path.getsize(web_config.invitations_file) > 0:
            try:
                saved_invitations = InvitationDict.load(web_config.invitations_file, web_config.secret_key)
                invitations.set_contents(saved_invitations)
            except Exception:
                error(f"Invalid invitations file detected: {web_config.invitations_file}")
                raise
        else:
            invitations.clear()
        if "wireguard" in config:
            wireguard_config.load(config["wireguard"])
            wireguard_config.apply()
        if "traffic" in config:
            traffic_config.load(config["traffic"])
            traffic_config.apply()
        info(f"Configuration restored!")

    def save(self, apply: bool = True):
        info("Saving configuration...")
        config = {
            "logger": logger_config,
            "web": web_config,
            "wireguard": wireguard_config,
            "traffic": traffic_config,
        }
        try_makedir(os.path.dirname(self.config_filepath))
        with open(self.config_filepath, "w") as file:
            yaml.safe_dump(config, file)
        info("Configuration saved!")
        if not apply:
            return
        logger_config.apply()
        wireguard_config.apply()
        web_config.apply()
        traffic_config.apply()
        self.save_identity_state()

    def reload_from_disk(self):
        self.__load_config__()
        from arpvpn.core.managers.tenancy import tenancy_manager
        tenancy_manager.initialize(
            legacy_users=users,
            legacy_interfaces=wireguard_config.interfaces,
            web_config=web_config,
            wireguard_config=wireguard_config,
        )

    @staticmethod
    def save_credentials():
        users.save(web_config.credentials_file, web_config.secret_key)

    @staticmethod
    def save_identity_state():
        ConfigManager.__save_encrypted_store__(users, web_config.credentials_file)
        ConfigManager.__save_encrypted_store__(tenants, web_config.tenants_file)
        ConfigManager.__save_encrypted_store__(invitations, web_config.invitations_file)

    @staticmethod
    def __save_encrypted_store__(store, path: str):
        if len(store) < 1:
            if os.path.exists(path):
                os.remove(path)
            return
        store.save(path, web_config.secret_key)


config_manager = ConfigManager()
