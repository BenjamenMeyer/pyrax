#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2014 Rackspace

# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json
import os
import uuid

import pyrax
from pyrax.client import BaseClient
import pyrax.exceptions as exc
from pyrax.manager import BaseManager
from pyrax.resource import BaseResource
import pyrax.utils as utils

# Because Cloud Backup v1 API uses Windows Timezone Names
import tzlocal
import tzlocal.windows_tz
import pytz


class TimeZones(BaseResource):
    """
    Available Timezones
    """
    def __init__(self, manager):
        self._manager = manager
        self._use_olsen_timezones = False
        if self._manager.get_api_version == 1:
            self._use_olsen_timezones = False

    
    def get_cloudbackup_timezone(self, timezone):
        """
        Return the appropriate timezone name by looking it up in the timezone mapping
        provided by tzlocal and pytz. If the timezone is not located there, then assume
        it is in the appropriate format and return it.
        """
        if self._use_olsen_timezones:
            # Windows to Olsen
            if timezone in tzlocal.windows_tz.win_tz:
                return tzlocal.windows_tz.win_tz[timezone]
            elif timezone in tzlocal.windows_tz.tz_win.keys():
                return timezone
            else:
                raise exc.InvalidTimeZone("Invalid timezone specified. Only Olsen Timezone Names allowed"
        else:
            if timezone in tzlocal.windows_tz.tz_win:
                return tzlocal.windows_tz.tz_win[timezone]
            elif timezone in tzlocal.windows_tz.win_tz.keys():
                return timezone
            else:
                raise exc.InvalidTimeZone("Invalid timezone specified. Only MS Windows Timezone Names allowed"


class BackupConfiguration(BaseResource):
    """
    Describes a single backup configuration
    """
    def __init__(self, backup_manager):
        self._manager = backup_manager
        self._data = {}
        self._data["BackupConfigurationName"] = None
        self._data["MachineAgentId"] = None
        self._data["IsActive"] = None
        self._data["VersionRetention"] = None
        self._data["BackupConfigurationScheduled"] = None
        self._data["MissedBackupActionId"] = None
        self._data["Frequency"] = None
        self._data["StartTimeHour"] = None
        self._data["StartTimeMinute"] = None
        self._data["StartTimeAmPm"] = None
        self._data["DayOfWeekId"] = None
        self._data["HourInterval"] = None
        self._data["TimeZoneId"] = None
        self._data["NotifyRecipients"] = None
        self._data["NotifySuccess"] = None
        self._data["NotifyFailure"] = None
        self._data["Inclusions"] = []
        self._data["Exclusions"] = []

    def get_configuration(self):
        return self._data

    @property
    def name(self):
        return self._data["BackupConfigurationName"]
    
    @name.setter
    def name(self, new_name)
        self._data["BackupConfigurationName"] = new_name

    @property
    def machine_agent_id(self):
        return self._data["MachineAgentId"]

    @machine_agent_id.setter
    def machine_agent_id(self, agent_id):
        if isinstance(agent_id, types.IntType):
            self._data["MachineAgentId"] = agent_id
        else:
            raise exc.InvalidSetting("machine agent id must be an integer")

    @property
    def active(self):
        return self._data["IsActive"]

    @active.setter
    def active(self, set_active):
        if set_active in (True, False):
            self._data["IsActive"] = set_active
        else:
            raise exc.InvalidSetting("active may only be True or False")

    @property
    def retention(self):
        return self._data["VersionRetention"]

    @retention.setter
    def retention(self, retention_period):
        if retention_period in (0, 30, 60):
            self._data["VersionRetention"] = retention_period
        else:
            raise exc.InvalidSetting("Retention Periods are 0 (infinite), 30, and 60.")

    @property
    def schedule(self):
        return self._data["BackupConfigurationScheduled"]

    @schedule.setter
    def schedule(self, new_schedule):
        self._data["BackupConfigurationScheduled"] = new_schedule

    @property
    def missed_backup_action(self):
        return self._data["MissedBackupActionId"]

    @missed_backup_action.setter
    def missed_backup_action(self, action_id):
        if action_id in (1, 2):
            self._data["MissedBackupActionId"] = action_id
        else:
            raise exc.InvalidSetting("Missed Backup Action Id may be 1 (send ASAP) or 2 (send at next scheduled time)")

    @property
    def frequency(self):
        return self._data["Frequency"]

    @frequency.setter
    def frequency(self, reoccurence):
        if isinstance(reoccurence, types.StringTypes):
            valid_values = ("Manually", "Hourly", "Daily", "Weekly")
            if reoccurence in valid_values:
                self._data["Frequency"] = reoccurence
            else:
                raise exc.InvalidSetting("Frequency may only be one of: Manually, Hourly, Daily, Weekly")
        else:
            raise exc.InvalidSetting("Frequency may only be one of: Manually, Hourly, Daily, Weekly")

    @property
    def start_hour(self):
        return self._data["StartTimeHour"]

    @start_hour.setter
    def start_hour(self, hour):
        if isinstance(hour, types.IntTypes) or isinstance(hour, types.NoneType):
            if (hour >=1 and hour <=12) or hour is None:
                self._data["StartTimeHour"] = hour
            else:
                raise exc.InvalidSetting("Start Time Hour may be either None or range from 1-12")
        else:
            raise exc.InvalidSetting("Start Time Hour may be either None or range from 1-12")

    @property
    def start_minute(self):
        return self._data["StartTimeMinute"]

    @start_minute.setter
    def start_minute(self, minute):
        if isinstance(minute, types.IntType) or isinstance(minute, types.NoneType):
            if (minute >= 0 and minute <= 59) or minute is None:
                self._data["StarTimeMinute"] = minute
            else:
                raise exc.InvalidSetting("Start Time Minute may either be None or range from 0-59")
        else:
            raise exc.InvalidSetting("Start Time Minute may either be None or range from 0-59")

    @property
    def start_time_ampm(self):
        return self._data["StartTimeAmPm"]

    @start_time_ampm.setter
    def start_time_ampm(self, am_pm):
        if isinstance(am_pm, types.StringTypes) or isinstance(am_pm, types.NoneType):
            if isinstance(am_pm, types.StringTypes):
                am_pm = am_pm.upper()
            valid_values = ("AM", "PM", None)
            if am_pm in valid_values:
                self._data["StartTimeAmPm"] = am_pm
            else:
                raise exc.InvalidSetting('Start Time AM/PM may either be None, "AM", or "PM"')
        else:
            raise exc.InvalidSetting('Start Time AM/PM may either be None, "AM", or "PM"')

    @property
    def day_of_week(self):
        return self._data["DayOfWeekId"]

    @day_of_week.setter
    def day_of_week(self, dow_id):
        if isinstance(dow_id, types.IntType) or isinstance(dow_id, types.NoneType):
            if (dow_id >= 0 and dow_id <= 6) or dow_id is None:
                self._data["DayOfWeekId"] = dow_id
            else:
                raise exc.InvalidSetting("Day of Week may either be None or range from 0-6 for Sunday-Saturday respectively")
        else:
            raise exc.InvalidSetting("Day of Week may either be None or range from 0-6 for Sunday-Saturday respectively")

    @property
    def hour_interval(self):
        return self._data["HourInterval"]

    @hour_interval.setter
    def hour_interval(self, interval):
        if isinstance(interval, types.IntType) or isinstance(interval, types.NoneType):
            if (interval >= 0 and interval <= 23) or interval is None:
                self._data["HourInterval"] = interval
            else:
                raise exc.InvalidSetting("Hour Interval may either be None or range from 0 to 23")
        else:
            raise exc.InvalidSetting("Hour Interval may either be None or range from 0 to 23")

    @property
    def timezone(self):
        return self._data["TimeZoneId"]

    @timezone.setter
    def timezone(self, tz):
        if isinstance(tz, types.StringType):
            self._data["TimeZoneId"] = tz
        else:
            exc.InvalidSettings("Timezone must be a string.")

    @property
    def notify_recipients(self):
        return self._data["NotifyRecipients"]

    @notify_recipients.setter
    def notify_recipients(self, notify):
        if isinstance(notify, types.StringType):
            self._data["NotifyRecipients"] = notify
        elif isinstance(notify, types.ListType):
            # Note: Test whether this works
            self._data["NotifyRecipients"] = ",".join(notify)
        else:
            raise exc.InvalidSettings("Notify Recipients must be either an e-mail address or a list of e-mail addresses")

    @property
    def notify_success(self):
        return self._data["NotifySuccess"]

    @notify_success.setter
    def notify_success(self, notify):
        if isinstance(notify, types.BooleanType):
            self._data["NotifySuccess"] = notify
        else:
            raise exc.InvalidSetting("Notify Success must be a Boolean type.")

    @property
    def notify_failure(self):
        return self._data["NotifyFailure"]

    @notify_failure.setter
    def notify_failure(self, notify):
        if isinstance(notify, types.BooleanType):
            self._data["NotifyFailure"] = notify
        else:
            raise exc.InvalidSetting("Notify Failure must be a Boolean type.")

    @property
    def inclusions(self):
        return self._data["Inclusions"]

    @inclusions.setter
    def inclusions(self, absolute_paths):
        if isinstance(absolute_paths, types.ListType):
            self._data["Inclusions"] = absolute_paths
        else:
            raise exc.InvalidSetting("Backup Inclusions must be a list of file and/or folder paths")

    @property
    def exclusions(self):
        return self._data["Exclusions"]

    @exclusions.setter
    def exclusions(self, absolute_paths):
        if isinstance(absolute_paths, types.ListType):
            self._data["Exclusions"] = absolute_paths
        else:
            raise exc.InvalidSettings("Backup Exclusions must be a list of file and/or folder paths")

    def add_path(self, path, exclude=False):
        if isinstance(path, types.StringTypes):
            if not exclude:
                self._data["Inclusions"].append(path)
            else:
                self._data["Exclusions"].append(path)
        else:
            raise exc.InvalidSetting("Path must be a string value")

    def remove_path(self, path, exclude=False):
        if isinstance(path, types.StringTypes):
            if not exclude:
                self._data["Inclusions"].remove(path)
            else:
                self._data["Exclusions"].remove(path)
        else:
            raise exc.InvalidSettings("Path must be a string value")


class RestoreConfiguration(BaseResource):
    """
    Describes a single restore configuration
    """
    def __init__(self, restore_manager):
        self._manager = restore_manager
        self._data = {}
        self._data["RestoreId"] = None
        self._data["BackupId"] = None
        self._data["BackupMachineId"] = None
        self._data["DestinationMachineId"] = None
        self._data["OverwriteFiles"] = None
        self._data["BackupConfiguratioId"] = None
        self._data["BackupConfigurationName"] = None
        self._data["BackupRestorePoint"] = None
        self._data["MachineAgentId"] = None
        self._data["BackupMachineName"] = None
        self._data["BackupFlavor"] = None
        self._data["DestinationMachineName"] = None
        self._data["DestinationPath"] = None
        self._data["IsEncrypted"] = None
        self._data["EncryptedPassword"] = None
        self._data["PublicKey"] = None
        self._data["RestoreStateId"] = None
        self._data["Inclusions"] = []
        self._data["Exclusions"] = []

    def get_configuration(self):
        return self._data

    @property
    def restore_id(self):
        return self._data["RestoreId"]

    @restore_id.setter
    def restore_id(self, rid):
        self._data["RestoreId"] = rid
    
    @property
    def backup_id(self):
        return self._data["BackupId"]

    @backup_id.setter
    def backup_id(self, bid):
        self._data["BackupId"] = bid

    @property
    def backup_machine_id(self):
        return self._data["BackupMachineId"]

    @backup_machine_id.setter
    def backup_machine_id(self, bmid):
        self._data["BackupMachineId"] = bmid

    @property
    def destination_machine_id(self);
        return self._data["DestinationMachineId"]

    @destination_machine_id
    def destination_machine_Id(self, dmid):
        self._data["DestinationMachineId"] = dmid

    @property
    def overwrite(self):
        return self._data["OverwriteFiles"]

    @overwrite.setter
    def overwrite(self, overwrite_files):
        if isinstance(overwrite_files, types.BooleanType):
            self._data["OverwriteFiles"] = overwrite_files
        else:
            exc.InvalidSetting("Overwrite must be a boolean type")
            

    @property
    def backup_configuration_id(self):
        return self._data["BackupConfigurationId"]

    @backup_configuration_id.setter
    def backup_configuration_id(self, bcid):
        self._data["BackupConfigurationId"] = bcid

    @property
    def backup_configuration_name(self):
        return self._data["BackupConfigurationName"]

    @backup_configuration_name.setter
    def backup_configuration_name(self, name):
        self._data["BackupCOnfigurationName"] = name

    @property
    def backup_restore_point(self):
        return self._data["BackupRestorePoint"]

    @backup_restore_point.setter
    def backup_restore_point(self, burp):
        self._data["BackupRestorePoint"] = burp

    @property
    def machine_agent_id(self):
        return self._data["MachineAgentId"]

    @machine_agent_id.setter
    def machine_agent_id(self, agent_id):
        if isinstance(agent_id, types.IntType):
            self._data["MachineAgentId"] = agent_id
        else:
            raise exc.InvalidSetting("machine agent id must be an integer")

    @property
    def backup_machine_name(self):
        return self._data["BackupMachineName"]

    @backup_machine_name.setter
    def backup_machine_name(self, name):
        self._data["BackupMachineName"] = name

    @property
    def backup_flavor(self):
        return self._data["BackupFlavor"]

    @backup_flavor.setter
    def backup_flavor(self, flavor):
        self._data["BackupFlavor"] = flavor

    @property
    def destination_machine_name(self):
        return self._data["DestinationMachineName"]

    @destination_machine_name.setter
    def destination_machine_name(self, name):
        self._data["DestinationMachineName"] = name

    @property
    def destination_path(self):
        return self._data["DestinationPath"]

    @destination_path.setter
    def destionation_path(self, path):
        self._data["DestionationPath"] = path

    @property
    def encrypted(self):
        return self._data["IsEncrypted"]

    @encrypted.setter
    def encrypted(self, encrypted_status):
        if isinstance(encrypted_status, types.BooleanType):
            self._data["IsEncrypted"] = encrypted_status
        else;
            raise exc.InvalidSetting("Encrypted must be boolean type")

    @property
    def encrypted_password(self):
        return self._data["EncryptedPassword"]

    @encrypted_password.setter
    def encrypted_password(self, pwd):
        self_data["EncryptedPassword"] = pwd

    @property
    def encrypted_publickey(self):
        return self._data["PublicKey"]

    @encrypted_publickey.setter
    def encrypted_publickey(self, pubkey):
        self._data["PublicKey"] = pubkey

    @property
    def restore_state_id(self):
        return self._data["RestoreStateId"]

    @restore_state_id.setter
    def restore_state_id(self, state):
        self._data["RestoreStateId"] = state

    @property
    def inclusions(self):
        return self._data["Inclusions"]

    @inclusions.setter
    def inclusions(self, absolute_paths):
        if isinstance(absolute_paths, types.ListType):
            self._data["Inclusions"] = absolute_paths
        else:
            raise exc.InvalidSetting("Backup Inclusions must be a list of file and/or folder paths")

    @property
    def exclusions(self):
        return self._data["Exclusions"]

    @exclusions.setter
    def exclusions(self, absolute_paths):
        if isinstance(absolute_paths, types.ListType):
            self._data["Exclusions"] = absolute_paths
        else:
            raise exc.InvalidSettings("Backup Exclusions must be a list of file and/or folder paths")

    def add_path(self, path, exclude=False):
        if isinstance(path, types.StringTypes):
            if not exclude:
                self._data["Inclusions"].append(path)
            else:
                self._data["Exclusions"].append(path)
        else:
            raise exc.InvalidSetting("Path must be a string value")

    def remove_path(self, path, exclude=False):
        if isinstance(path, types.StringTypes):
            if not exclude:
                self._data["Inclusions"].remove(path)
            else:
                self._data["Exclusions"].remove(path)
        else:
            raise exc.InvalidSettings("Path must be a string value")



class AgentDetails(BaseResource):
    """
    Describes a single cloud backup agent instance
    """
    def __init__(self, agent_manager):
        self._manager = agent_manager
        self._data = {}
        self._data["AgentVersion"] = None
        self._data["Architecture"] = None
        self._data["Flavor"] = None
        self._data["BackupVaultSize"] = None
        self._data["CleanupAllowed"] = None
        self._data["Datacenter"] = None
        self._data["IPAddress"] = None
        self._data["IsDisabled"] = None
        self._data["IsEncrypted"] = None
        self._data["MachineAgentId"] = None
        self._data["MachineName"] = None
        self._data["OperatingSystem"] = None
        self._data["OperatingSystemVersion"] = None
        self._data["PublicKey"] = None
        self._data["Status"] = None
        self._data["TimeOfLastSuccessfulBackup"] = None
        self._data["UseServiceNet"] = None
        self._data["HostServerId"] = None

    @property
    def version(self):
        return self._data["AgentVersion"]

    @version.setter
    def version(self, ver):
        self._data["AgentVersion"] = ver
        
    @property
    def architecture(self):
        return self._data["Architecture"]

    @architecture.setter
    def architecture(self, arch):
        self._data["Architecture"] = arch

    @property
    def flavor(self):
        return self._data["Flavor"]

    @flavor.setter
    def flavor(self, flvr):
        self._data["Flavor"] = flvr

    @property
    def backup_vault_size(self):
        return self._data["BackupVaultSize"]

    @backup_vault_size.setter
    def backup_vault_size(self, size):
        self._data["BackupVaultSize"] = size

    @property
    def allow_cleanup(self):
        return self._data["CleanupAllowed"]

    @allow_cleanup.setter
    def allow_cleanup(self, allow):
        self._data["CleanupAllowed"] = allow

    @property
    def datacenter(self):
        return self._data["Datacenter"]

    @datacenter.setter
    def dataceneter(self, dc):
        self._data["Datacenter"] = dc

    @property
    def ip_address(self):
        return self._data["IPAddress"]

    @ip_address.setter
    def ip_address(self, address):
        self._data["IPAddress"] = address

    @property
    def disabled(self):
        return self._data["IsDisabled"]

    @disabled.setter
    def disabled(self, status):
        self._data["IsDisabled"] = status

    @property
    def enabled(self):
        return not self.disabled

    @enabled.setter
    def enabled(self, status)
        self.disabled = not status

    @property
    def encrypted(self):
        return self._data["IsEncrypted"]

    @encrypted.setter
    def encrypted(self, status):
        self._data["IsEncrypted"] = status

    @property
    def machine_agent_id(self):
        return self._data["MachineAgentId"]

    @machine_agent_id.setter
    def machine_agent_id(self, agent_id):
        self._data["MachineAgentId"] = agent_id

    @property
    def machine_name(self):
        return self._data["MachineName"]

    @machine_name.setter
    def machine_name(self, name):
        self._data["MachineName"] = name

    @property
    def os(self):
        return self._data["OperatingSystem"]

    @os.setter
    def os(self, os_name):
        self._data["OperatingSystem"] = os_name

    @property
    def os_version(self):
        return self._data["OperatingSystemVersion"]

    @os_version.setter
    def os_version(self, ver):
        self._data["OperatingSystemVersion"] = ver

    @property
    def encrypted_publickey(self):
        return self._data["PublicKey"]

    @encrypted_publickey.setter
    def encrypted_publickey(self, pubkey):
        self._data["PublicKey"] = pubkey

    @property
    def status(self)
        return self._data["Status"]

    @status.setter
    def status(self, stat):
        self._data["Status"] = stat

    @property
    def last_successful_backup_time(self):
        return self._data["TimeOfLastSuccessfulBackup"]

    @last_successful_backup_time.setter
    def last_successful_backup_time(self, backup_time):
        self._data["TimeOfLastSuccessfulBackup"] = backup_time

    @property
    def use_servicenet(self):
        return self._data["UseServiceNet"]

    @use_servicenet.setter
    def use_servicenet(self, enabled):
        self._data["UseServiceNet"] = enabled

    @property
    def host_server_id(self):
        return self._data["HostServerId"]

    @host_server_id.setter(self):
    def host_server_id(self, hsid):
        self._data["HostServerId"] = hsid


class BackupManager(BaseManager):
    """
    Manage backups for a given cloud backup agent instance
    """
    def __init__(self, agent_manager):
        self._manager = agent_manager
        self._configurations = list()

    def get_configurations(self):
        pass

    def add_configuration(self, configuration):
        pass

    def update_configuration(self, configuration):
        pass

    def delete_configuration(self, configuration):
        pass

    def start_backup(self, configuration):
        pass

    def stop_backup(self, configuration):
        pass

    def monitor_backup(self, configuration, callback=None);
        pass


class RestoreManager(BaseManager):
    """
    Manage restores for a given cloud backup agent instance
    """
    def __init__(self, agent_manager):
        self._manager = agent_manager
        self._configurations = list()

    def get_configurations(self):
        pass

    def add_configuration(self, configuration):
        pass

    def update_configuration(self, configuration):
        pass

    def delete_configuration(self, configuration):
        pass
    
    def start_restore(self, configuration):
        pass

    def stop_restore(self, configuration):
        pass

    def monitor_restore(self, configuration, callback=None):
        pass


class Agent(BaseManager):
    """
    Manages a single cloud backup agent instance
    """
    def __init__(self, manager, machine_agent_id):
        self._manager = manager
        self._agent_id = machine_agent_id
        self._details = AgentDetails(self) 

    def get_machine_agent_id(self):
        return self._machine_agent_id

    def get_agent_details(self):
        #TODO: Retrieve the agent details
        return self._details


class AgentManager(BaseManager):
    """
    Manages multiple agent instances
    """
    def __init__(self, manager):
        self._manager = manager
        self._backups = BackupManager(self)
        self._restores = RestoreManager(self)
        self._agents = {}

    def get_backup_manager(self):
        return self._backups

    def get_restore_manager(self):
        return self._restores


class __CloudBackupRseData(object):
    """
    Class to manage the RSE specific data, namely the UUID and User Agent in an easy manner
    """
    def __init__(self, app, app_version):
        self.app = app
        self.app_version = app_version
        # Generate a unique identifier for the talking with RSE. This must change with the app version.
        self.uuid = uuid.uuid5(uuid.NAMESPACE_URL, ("pyrax.rcbu.rackspace.com/" + self.app + "/" + self.app_version)
        self.user_agent = self.app + "/" + self.app_version + " uuid/" + str(self.uuid)

    @property
    def rse_user_agent(self):
        """
        Return the active RSE User Agent String
        """
        return self.user_agent

    @property
    def uuid(self):
        """
        Return the UUID that will be used with RSE for the application and application version
        """
        return self.uuid

    @property
    def app(self):
        """
        Return the application name
        """
        return self.app

    @property
    def app_version(self):
        """
        Return the application version
        """
        return self.app_version


class __CloudBackupRse(BaseClient):
    """
    Interface for Cloud Backup RSE which is utilized for interacting with
    the Cloud Backup Agent
    """
    def __init__(self, agent, api_host, app, app_version, authenticator, agent_rse_key, rse_direct=False):
        self._agent = agent
        self._rse_direct = rse_direct
        self._api_host = api_host
        self._rse_data = _CloudBackupRseData(app, app_version)
        self._authenticator = authenticator
        self._agent_rse_key = agent_rse_key
        self._headers = {}
        if _self.rse_direct:
            self._uri = self._agent.get_rse_host()
            self._rse_channel = self._agent.get_rse_channel()
        else:
            self._uri = "https://" + api_host + "/v1.0/agent/events"

    def _setup_headers(self):
        self._headers = {}
        self._headers["X-Auth-Token"] = self._authenticator.get_token()
        if self._rse_direct:
            self._headers["X-Agent-Key"] = self._agent_rse_key
            self._headers["X-RSE-Version"] = "2011-05-01"
            self._headers["User-Agent"] = self._rse_data.rse_user_agent()


    def _call(self, mthd, machine_agent_id, data):
        kwargs = {"headers": self._headers}
        if data:
            kwargs["body"] = data
        uri = self._uri + "/" + str(machine_agent_id)
        return pyrax.http.request(mthd, uri, **kwargs)


    def method_post(self, machine_agent_id, data=None):
        return self._call("POST", data)


    def query(self, machine_agent_id):
        """
        Retrieve a record set from RSE
        """
        resp, resp_body = method_get(machine_agent_id)
        if resp.status_code == 200:
            return resp_body.json()
        else:
            raise exc.ServiceResponseFailure("Failed to receive valid response from RSE") 


    def detect_heartbeat(self, machine_agent_id):
        """
        Check the RSE Channel for the Heart Beat Message for a given agent
        """
        try:
            rse_msg = self.query(machine_agent_id)
            if 'events' in rse_msg:
                for event in rse_msg['events']:
                    if event['data']['Event'] == 'Heartbeat':
                        if event['data']['MachineAgentId'] == machine_agent_id
                            return True
                return False
            else:
                for event in rse_msg:
                    if event['data'['Event'] == 'Heartbeat':
                        if event['data']['MachineAgentId'] == machine_agent_id
                            return True
                return False
        except LookupError:
            return False



class __CloudBackupApiV1(BaseClient):
    """
    Implements the v1 API set for Cloud Backup.
    """
    pass


class CloudBackup(BaseManager):
    """
    This manages the user's cloud backups for all systems owned by the user.
    """
    pass

