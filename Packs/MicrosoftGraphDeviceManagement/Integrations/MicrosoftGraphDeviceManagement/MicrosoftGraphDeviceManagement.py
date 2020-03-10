import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
from typing import Tuple, Any
import json

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBAL VARS '''

EMPTY_RESP_TYPE = 'None'

HEADERS: dict = {
    'raw_device': ['id', 'userId', 'deviceName', 'operatingSystem', 'osVersion', 'emailAddress',
                   'manufacturer', 'model', 'imei', 'meid'],
    'device': ['ID', 'User ID', 'Device Name', 'Operating System', 'OS Version', 'Email Address',
               'Manufacturer', 'Model', 'IMEI', 'MEID']
}


''' CLIENT '''


class MsGraphClient:
    def __init__(self, ms_client):
        self.ms_client = ms_client

    def list_managed_devices(self, args: dict) -> Tuple[list, Any]:
        url_suffix: str = '/deviceManagement/managedDevices'
        limit: int = try_parse_integer(args.get('limit', 10), err_msg='This value for limit must be an integer.')
        raw_response = self.ms_client.http_request('GET', url_suffix)
        return raw_response.get('value', [])[:limit], raw_response

    def get_managed_device(self, args: dict) -> Tuple[Any, str]:
        device_id: str = str(args.get("device_id"))
        url_suffix: str = f'/deviceManagement/managedDevices/{device_id}'
        return self.ms_client.http_request('GET', url_suffix), device_id

    def make_action(self, args: dict, action: str, body: str = None) -> None:
        url_suffix: str = f'deviceManagement/managedDevices/{args.get("device_id")}/{action}'
        self.ms_client.http_request('POST', url_suffix, data=body, resp_type=EMPTY_RESP_TYPE)

    def delete_user_from_shared_apple_device(self, args: dict, action: str) -> None:
        body: dict = {'userPrincipalName': args.get('user_principal_name')}
        self.make_action(args, action, json.dumps(body))

    def clean_windows_device(self, args: dict, action: str) -> None:
        body: dict = {'keepUserData': bool(args.get('keep_user_data'))}
        self.make_action(args, action, json.dumps(body))

    def windows_device_defender_scan(self, args: dict, action: str) -> None:
        body: dict = {'quickScan': bool(args.get('quick_scan'))}
        self.make_action(args, action, json.dumps(body))

    def wipe_device(self, args: dict, action: str) -> None:
        body: dict = {
            'keepEnrollmentData': bool(args.get('keep_enrollment_data')),
            'keepUserData': bool(args.get('keep_user_data'))
        }
        mac_os_unlock_code: str = str(args.get('mac_os_unlock_code'))
        if mac_os_unlock_code:
            body['macOsUnlockCode'] = mac_os_unlock_code
        self.make_action(args, action, json.dumps(body))

    def update_windows_device_account(self, args: dict, action: str) -> None:
        body: dict = {
            'updateWindowsDeviceAccountActionParameter': {
                '@odata.type': 'microsoft.graph.updateWindowsDeviceAccountActionParameter',
                'deviceAccount': {
                    '@odata.type': 'microsoft.graph.windowsDeviceAccount',
                    'password': args.get('device_account_password')
                },
                'passwordRotationEnabled': bool(args.get('password_rotation_enabled')),
                'calendarSyncEnabled': bool(args.get('calendar_sync_enabled')),
                'deviceAccountEmail': args.get('device_account_email'),
                'exchangeServer': args.get('exchange_server'),
                'sessionInitiationProtocalAddress': args.get('session_initiation_protocal_address')
            }
        }
        self.make_action(args, action, json.dumps(body))


''' HELPER FUNCTIONS '''


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    :param int_to_parse: The argument to be parsed into integer
    :param err_msg: The error message to show in case of failure
    :return: The integer
    """
    try:
        res: int = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def parse_device_action_results(raw_device_action_results: list) -> list:
    """
    Parses a list of device action results
    :param raw_device_action_results: The raw list of device action results
    :return: The parsed list of device action results
    """
    action_results: list = list()
    for device_action_result in raw_device_action_results:
        action_result = assign_params(**{
            'Name': device_action_result.get('actionName'),
            'State': device_action_result.get('actionState'),
            'StartDateTime': device_action_result.get('startDateTime'),
            'LastUpdatedDateTime': device_action_result.get('lastUpdatedDateTime')
        })
        if action_result:
            action_results.append(action_result)
    return action_results


def build_device_object(raw_device: dict) -> dict:
    """
    Builds a device context object
    :param raw_device: The raw device object
    :return: The device context object
    """
    device_action_results: list = raw_device.get('deviceActionResults', []) if raw_device.get('deviceActionResults') \
        else []
    conf_manager_client_enabled_features: dict = raw_device.get('configurationManagerClientEnabledFeatures', {}) \
        if raw_device.get('configurationManagerClientEnabledFeatures') else {}
    device_health_attestation_state: dict = raw_device.get('deviceHealthAttestationState', {}) \
        if raw_device.get('deviceHealthAttestationState') else {}
    return assign_params(**{
        'ID': raw_device.get('id'),
        'UserID': raw_device.get('userId'),
        'Name': raw_device.get('deviceName'),
        'ManagedDeviceOwnerType': raw_device.get('managedDeviceOwnerType'),
        'ActionResults': parse_device_action_results(device_action_results),
        'EnrolledDateTime': raw_device.get('enrolledDateTime'),
        'LastSyncDateTime': raw_device.get('lastSyncDateTime'),
        'OperatingSystem': raw_device.get('operatingSystem'),
        'ComplianceState': raw_device.get('complianceState'),
        'JailBroken': raw_device.get('jailBroken'),
        'ManagementAgent': raw_device.get('managementAgent'),
        'OSVersion': raw_device.get('osVersion'),
        'EASDeviceID': raw_device.get('easDeviceId'),
        'EASActivationDateTime': raw_device.get('easActivationDateTime'),
        'ActivationLockBypassCode': raw_device.get('activationLockBypassCode'),
        'EmailAddress': raw_device.get('emailAddress'),
        'AzureADDeviceID': raw_device.get('azureADDeviceId'),
        'CategoryDisplayName': raw_device.get('deviceCategoryDisplayName'),
        'ExchangeAccessState': raw_device.get('exchangeAccessState'),
        'ExchangeAccessStateReason': raw_device.get('exchangeAccessStateReason'),
        'IsSupervised': raw_device.get('isSupervised'),
        'IsEncrypted': raw_device.get('isEncrypted'),
        'UserPrincipalName': raw_device.get('userPrincipalName'),
        'Model': raw_device.get('model'),
        'Manufacturer': raw_device.get('manufacturer'),
        'IMEI': raw_device.get('imei'),
        'SerialNumber': raw_device.get('serialNumber'),
        'PhoneNumber': raw_device.get('phoneNumber'),
        'AndroidSecurityPatchLevel': raw_device.get('androidSecurityPatchLevel'),
        'ConfigurationManagerClientEnabledFeatures': assign_params(**{
            'Inventory': conf_manager_client_enabled_features.get('inventory'),
            'ModernApps': conf_manager_client_enabled_features.get('modernApps'),
            'ResourceAccess': conf_manager_client_enabled_features.get('resourceAccess'),
            'DeviceConfiguration': conf_manager_client_enabled_features.get('deviceConfiguration'),
            'CompliancePolicy': conf_manager_client_enabled_features.get('compliancePolicy'),
            'WindowsUpdateForBusiness': conf_manager_client_enabled_features.get('windowsUpdatesForBusiness')
        }),
        'WiFiMacAddress': raw_device.get('wiFiMacAddress'),
        'HealthAttestationState': assign_params(**{
            'LastUpdateDateTime': device_health_attestation_state.get('lastUpdateDateTime'),
            'IssuedDateTime': device_health_attestation_state.get('issuedDateTime'),
            'ResetCount': device_health_attestation_state.get('resetCount'),
            'RestartCount': device_health_attestation_state.get('restartCount'),
            'BitLockerStatus': device_health_attestation_state.get('bitLockerStatus'),
            'BootManagerVersion': device_health_attestation_state.get('bootManagerVersion'),
            'SecureBoot': device_health_attestation_state.get('secureBoot'),
            'BootDebugging': device_health_attestation_state.get('bootDebugging'),
            'OperatingSystemKernelDebugging': device_health_attestation_state.get('operatingSystemKernelDebugging'),
            'CodeIntegrity': device_health_attestation_state.get('codeIntegrity'),
            'TestSigning': device_health_attestation_state.get('testSigning'),
            'SafeMode': device_health_attestation_state.get('safeMode'),
            'WindowsPE': device_health_attestation_state.get('windowsPE'),
            'EarlyLaunchAntiMalwareDriverProtection':
                device_health_attestation_state.get('earlyLaunchAntiMalwareDriverProtection'),
            'VirtualSecureMode': device_health_attestation_state.get('virtualSecureMode'),
            'PCRHashAlgorithm': device_health_attestation_state.get('pcrHashAlgorithm'),
            'BootAppSecurityVersion': device_health_attestation_state.get('bootAppSecurityVersion'),
            'BootManagerSecurityVersion': device_health_attestation_state.get('bootManagerSecurityVersion'),
            'TPMVersion': device_health_attestation_state.get('tpmVersion'),
            'PCR0': device_health_attestation_state.get('pcr0'),
            'SecureBootConfigurationPolicyFingerPrint':
                device_health_attestation_state.get('secureBootConfigurationPolicyFingerPrint'),
            'CodeIntegrityPolicy': device_health_attestation_state.get('codeIntegrityPolicy'),
            'BootRevisionListInfo': device_health_attestation_state.get('bootRevisionListInfo'),
            'OperatingSystemRevListInfo': device_health_attestation_state.get('operatingSystemRevListInfo'),
            'HealthStatusMismatchInfo': device_health_attestation_state.get('healthStatusMismatchInfo'),
            'HealthAttestationSupportedStatus': device_health_attestation_state.get('healthAttestationSupportedStatus')
        }),
        'SubscriberCarrier': raw_device.get('subscriberCarrier'),
        'MEID': raw_device.get('meid'),
        'TotalStorageSpaceInBytes': raw_device.get('totalStorageSpaceInBytes'),
        'FreeStorageSpaceInBytes': raw_device.get('freeStorageSpaceInBytes'),
        'ManagedDeviceName': raw_device.get('managedDeviceName'),
        'PartnerReportedThreatState': raw_device.get('partnerReportedThreatState')
    })


def build_device_human_readable(device: dict) -> dict:
    """
    Builds a device human readable object
    :param device: The raw device object
    :return: The device human readable object
    """
    device_human_readable: dict = dict()
    for header in HEADERS['raw_device']:
        index: int = HEADERS['raw_device'].index(header)
        device_human_readable[HEADERS['device'][index]] = device.get(header)
    return assign_params(**device_human_readable)


''' COMMANDS '''


def list_managed_devices_command(client: MsGraphClient, args: dict) -> None:
    list_raw_devices, raw_response = client.list_managed_devices(args)
    list_devices: list = [build_device_object(device) for device in list_raw_devices if device]
    list_devices_hr: list = [build_device_human_readable(device) for device in list_raw_devices if device]
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': list_devices}
    human_readable: str = 'No managed devices found.'
    if list_devices:
        human_readable = tableToMarkdown('List managed devices', list_devices_hr, headers=HEADERS['device'])
    return_outputs(human_readable, entry_context, raw_response)


def get_managed_device_command(client: MsGraphClient, args: dict) -> None:
    raw_response, device_id = client.get_managed_device(args)
    device: dict = build_device_object(raw_response)
    device_hr: dict = build_device_human_readable(raw_response)
    entry_context: dict = {'MSGraphDeviceManagement.Device(val.ID === obj.ID)': device}
    device_name: str = device.get('Name', '')
    human_readable: str = f'Managed device {device_id} not found.'
    if device:
        human_readable = tableToMarkdown(f'Managed device {device_name}', device_hr, headers=HEADERS['device'])
    return_outputs(human_readable, entry_context, raw_response)


def disable_lost_mode_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'disableLostMode')
    return_outputs('Device disable lost mode action activated successfully.', {}, {})


def locate_device_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'locateDevice')
    return_outputs('Locate device action activated successfully.', {}, {})


def sync_device_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'syncDevice')
    return_outputs('Sync device action activated successfully.', {}, {})


def device_reboot_now_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'rebootNow')
    return_outputs('Device reboot now action activated successfully.', {}, {})


def device_shutdown_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'shutDown')
    return_outputs('Device shutdown action activated successfully.', {}, {})


def device_bypass_activation_lock_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'bypassActivationLock')
    return_outputs('Device bypass activation lock action activated successfully.', {}, {})


def device_retire_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'retire')
    return_outputs('Retire device action activated successfully.', {}, {})


def device_reset_passcode_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'resetPasscode')
    return_outputs('Device reset passcode action activated successfully.', {}, {})


def device_remote_lock_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'remoteLock')
    return_outputs('Device remote lock action activated successfully.', {}, {})


def device_request_remote_assistance_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'requestRemoteAssistance')
    return_outputs('Device request remote assistance action activated successfully.', {}, {})


def device_recover_passcode_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'recoverPasscode')
    return_outputs('Device recover passcode action activated successfully.', {}, {})


def logout_shared_apple_device_active_user_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'logoutSharedAppleDeviceActiveUser')
    return_outputs('Logout shard apple device active user action activated successfully.', {}, {})


def delete_user_from_shared_apple_device_command(client: MsGraphClient, args: dict) -> None:
    client.delete_user_from_shared_apple_device(args, 'deleteUserFromSharedAppleDevice')
    return_outputs('Delete user from shared apple device action activated successfully.', {}, {})


def windows_device_defender_update_signatures_command(client: MsGraphClient, args: dict) -> None:
    client.make_action(args, 'windowsDefenderUpdateSignatures')
    return_outputs('Windows device defender update signatures action activated successfully.', {}, {})


def clean_windows_device_command(client: MsGraphClient, args: dict) -> None:
    client.clean_windows_device(args, 'cleanWindowsDevice')
    return_outputs('Clean windows device action activated successfully.', {}, {})


def windows_device_defender_scan_command(client: MsGraphClient, args: dict) -> None:
    client.windows_device_defender_scan(args, 'windowsDefenderScan')
    return_outputs('Windows device defender scan action activated successfully.', {}, {})


def wipe_device_command(client: MsGraphClient, args: dict) -> None:
    client.wipe_device(args, 'wipe')
    return_outputs('Wipe device action activated successfully.', {}, {})


def update_windows_device_account_command(client: MsGraphClient, args: dict) -> None:
    client.update_windows_device_account(args, 'updateWindowsDeviceAccount')
    return_outputs('Update windows device account action activated successfully.', {}, {})


''' MAIN '''


def main():
    args: dict = demisto.args()
    params: dict = demisto.params()
    self_deployed: bool = params.get('self_deployed', False)
    tenant_id: str = params.get('tenant_id', '')
    auth_and_token_url: str = params.get('auth_id', '')
    enc_key: str = params.get('enc_key', '')
    # remove trailing slash to prevent wrong URL path to service
    url: str = params.get('url', '')
    server: str = url[:-1] if (url and url.endswith('/')) else url
    # service base URL
    base_url: str = server + '/v1.0'
    app_name: str = 'ms-graph-device-management'
    ok_codes: tuple = (200, 201, 202, 204)
    use_ssl: bool = not params.get('insecure', False)
    app_url: str = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token' if self_deployed else ''
    scope: str = 'https://graph.microsoft.com/.default' if self_deployed else ''

    proxy: dict = handle_proxy()

    ms_client = MicrosoftClient(self_deployed=self_deployed, tenant_id=tenant_id, auth_id=auth_and_token_url,
                                client_id=auth_and_token_url, enc_key=enc_key, client_secret=enc_key, app_name=app_name,
                                app_url=app_url, scope=scope, base_url=base_url, verify=use_ssl, proxy=proxy,
                                ok_codes=ok_codes)
    client: MsGraphClient = MsGraphClient(ms_client)

    command: str = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            client.ms_client.get_access_token()
            demisto.results('ok')
        elif command == 'msgraph-list-managed-devices':
            list_managed_devices_command(client, args)
        elif command == 'msgraph-get-managed-device-by-id':
            get_managed_device_command(client, args)
        elif command == 'msgraph-device-disable-lost-mode':
            disable_lost_mode_command(client, args)
        elif command == 'msgraph-locate-device':
            locate_device_command(client, args)
        elif command == 'msgraph-sync-device':
            sync_device_command(client, args)
        elif command == 'msgraph-device-reboot-now':
            device_reboot_now_command(client, args)
        elif command == 'msgraph-device-shutdown':
            device_shutdown_command(client, args)
        elif command == 'msgraph-device-bypass-activation-lock':
            device_bypass_activation_lock_command(client, args)
        elif command == 'msgraph-device-retire':
            device_retire_command(client, args)
        elif command == 'msgraph-device-reset-passcode':
            device_reset_passcode_command(client, args)
        elif command == 'msgraph-device-remote-lock':
            device_remote_lock_command(client, args)
        elif command == 'msgraph-device-request-remote-assistance':
            device_request_remote_assistance_command(client, args)
        elif command == 'msgraph-device-recover-passcode':
            device_recover_passcode_command(client, args)
        elif command == 'msgraph-logout-shared-apple-device-active-user':
            logout_shared_apple_device_active_user_command(client, args)
        elif command == 'msgraph-delete-user-from-shared-apple-device':
            delete_user_from_shared_apple_device_command(client, args)
        elif command == 'msgraph-windows-device-defender-update-signatures':
            windows_device_defender_update_signatures_command(client, args)
        elif command == 'msgraph-clean-windows-device':
            clean_windows_device_command(client, args)
        elif command == 'msgraph-windows-device-defender-scan':
            windows_device_defender_scan_command(client, args)
        elif command == 'msgraph-wipe-device':
            wipe_device_command(client, args)
        elif command == 'msgraph-update-windows-device-account':
            update_windows_device_account_command(client, args)

    # log exceptions
    except Exception as err:
        return_error(str(err))


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtins']:
    main()
