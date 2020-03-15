import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import json
import requests
import dateutil.parser
from datetime import date

requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''
BASE_URL = demisto.params().get('url')
if BASE_URL:
    if BASE_URL[-1] != '/':
        BASE_URL += '/'
API_KEY = demisto.params().get('apikey')
VERIFY_CERTIFICATE = False
FETCH_TIME = demisto.params().get('fetch_time', '')

''' COMMAND FUNCTIONS '''


def get_list(list_id):
    fullurl = BASE_URL + 'api/lists/{}/members.json'.format(list_id)
    res = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error(
            'Get list failed. URL: {}, StatusCode: {}, Response: {}'.format(fullurl, res.status_code, res.text))

    return res.json()


def get_list_command():
    ''' Retrieves all indicators of a the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    list_items = get_list(list_id)

    demisto.results({'list': list_items})


def add_to_list(list_id, indicator, comment, expiration):
    fullurl = BASE_URL + 'api/lists/{}/members.json'.format(list_id)

    indicator = {
        'member': indicator
    }
    if comment:
        indicator['description'] = comment

    if expiration:
        indicator['expiration'] = expiration

    res = requests.post(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE,
        json=indicator
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Add to list failed. URL: {}, Request Body: {}, StatusCode: {}, Response: {}'.format(
            fullurl, json.dumps(indicator), res.status_code, res.text))

    return res.json()


def add_to_list_command():
    ''' Adds given indicators to the given list ID in Threat Response '''
    list_id = demisto.args().get('list-id')
    indicators = argToList(demisto.args().get('indicator'))
    comment = demisto.args().get('comment')
    expiration = demisto.args().get('expiration')

    message = ''
    for indicator in indicators:
        add_to_list(list_id, indicator, comment, expiration)
        message += '{} added successfully to {}\n'.format(indicator, list_id)

    demisto.results(message)


def block_ip_command():
    ''' Adds given IPs to the relevant blacklist in Threat Response '''
    list_id = demisto.args().get('blacklist_ip')
    ips = argToList(demisto.args().get('ip'))
    expiration = demisto.args().get('expiration')

    message = ''
    for ip in ips:
        add_to_list(list_id, ip, None, expiration)
        message += '{} added successfully to block_ip list\n'.format(ip)

    demisto.results(message)


def block_domain_command():
    ''' Adds given domains to the relevant blacklist in Threat Response '''
    list_id = demisto.args().get('blacklist_domain')
    domains = argToList(demisto.args().get('domain'))
    expiration = demisto.args().get('expiration')

    message = ''
    for domain in domains:
        add_to_list(list_id, domain, None, expiration)
        message += '{} added successfully to block_domain list\n'.format(domain)

    demisto.results(message)


def block_url_command():
    ''' Adds given URLs to the relevant blacklist in Threat Response '''
    list_id = demisto.args().get('blacklist_url')
    urls = argToList(demisto.args().get('url'))
    expiration = demisto.args().get('expiration')

    message = ''
    for url in urls:
        add_to_list(list_id, url, None, expiration)
        message += '{} added successfully to block_url list\n'.format(url)

    demisto.results(message)


def block_hash_command():
    ''' Adds given hashes to the relevant blacklist in Threat Response '''
    list_id = demisto.args().get('blacklist_hash')
    hashes = argToList(demisto.args().get('hash'))
    expiration = demisto.args().get('expiration')

    message = ''
    for h in hashes:
        add_to_list(list_id, h, None, expiration)
        message += '{} added successfully to block_hash list\n'.format(h)

    demisto.results(message)


def search_indicators(list_id, indicator_filter):
    list_indicators = get_list(list_id)
    found_items = []
    for item in list_indicators:
        item_indicator = demisto.get(item, 'host.host')
        if indicator_filter in item_indicator:
            found_items.append(item)

    return found_items


def search_indicator_command():
    ''' Retrieves indicators of a list, using a filter '''
    list_id = demisto.args().get('list-id')
    indicator_filter = demisto.args().get('filter')
    found = search_indicators(list_id, indicator_filter)

    demisto.results({'indicators': found})


def delete_indicator(list_id, indicator_filter):
    indicator = search_indicators(list_id, indicator_filter)
    if len(indicator) == 0:
        return_error('{} not exists in {}'.format(indicator_filter, list_id))

    indicator_id = indicator.get('id')  # pylint: disable=E1101
    fullurl = BASE_URL + 'api/lists/{}/members/{}.json'.format(list_id, indicator_id)
    res = requests.delete(
        fullurl,
        headers={
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )
    if res.status_code < 200 or res.status_code >= 300:
        return_error(
            'Delete indicator failed. URL: {}, StatusCode: {}, Response: {}'.format(fullurl, res.status_code, res.text))


def delete_indicator_command():
    ''' Deletes an indicator from a list '''
    list_id = demisto.args().get('list-id')
    indicator = demisto.args().get('indicator')
    delete_indicator(list_id, indicator)

    demisto.results('{} deleted successfully from list {}'.format(list_id, indicator))


def test():
    """Perform API call to check that the API is accessible.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    get_incidents_request(
        {
            'created_after': date.today(),
            'state': 'open'
        })
    demisto.results('ok')


# TRAP API
def get_incident_field_context(incident):
    """Parses the 'incident_fields' entry of the incident and returns it
    Args:
        incident (dict): The incident to parse
    Returns:
        list. The parsed incident fields list
    """
    incident_field_values = []
    for incident_field in incident['incident_field_values']:
        incident_field_values.append({
            incident_field['name'].replace(" ", "_"): incident_field['value']
        })
    return incident_field_values


def get_emails_context(event):
    """Returns the context of the emails in the event
    Args:
        event (dict): The event to parse the emails from
    Returns:
        list. The parsed emails list from the event
    """
    emails_context = []
    for email in event['emails']:
        emails_context.append(
            assign_params(**{
                'sender': email.get('sender', {}).get('email'),
                'recipient': email.get('recipient', {}).get('email'),
                'subject': email.get('subject'),
                'message_id': email.get('messageId'),
                'message_delivery_time': email.get('messageDeliveryTime', {}).get('millis'),
                'body': email.get('body'),
                'body_type': email.get('bodyType'),
                'headers': email.get('headers'),
                'urls': email.get('urls')
            }))
    return emails_context


def create_incidents_context(incidents_list):
    """Parses the incidents list and returns the incidents context
    Args:
        incidents_list (list): The incidents list to parse
    Returns:
        list. The context created from the incidents list
    """
    context = incidents_list.copy()
    for incident in context:
        incident['incident_field_values'] = get_incident_field_context(incident)

        if incident.get('events'):
            for event in incident['events']:
                event['emails'] = get_emails_context(event)

    return context


def create_incidents_human_readable(human_readable_message, incidents_list):
    """Creates the human readable entry for incidents
    Args:
        human_readable_message (str): The title of the human readable table
        incidents_list (list): The incidents list to insert to the table

    Returns:
        str. The incidents human readable in markdown format
    """
    human_readable = []
    human_readable_headers = ['Created At', 'ID', 'Type', 'Summary', 'Score', 'Event Count', 'Assignee',
                              'Successful Quarantines', 'Failed Quarantines', 'Pending Quarantines']
    for incident in incidents_list:
        human_readable.append({
            'Created At': incident.get('created_at'),
            'ID': incident.get('id'),
            'Type': incident.get('type'),
            'Summary': incident.get('summary'),
            'Score': incident.get('score'),
            'Event Count': incident.get('event_count'),
            'Assignee': incident.get('assignee'),
            'Successful Quarantines': incident.get('successful_quarantine'),
            'Failed Quarantines': incident.get('failed_quarantines'),
            'Pending Quarantines': incident.get('pending_quarantines')
        })

    return tableToMarkdown(human_readable_message, human_readable, human_readable_headers)


def list_incidents_command():
    """
        Retrieves incidents from ProofPoint API
    """
    args = demisto.args()
    limit = int(args.pop('limit'))

    incidents_list = get_incidents_request(args)

    incidents_list = incidents_list[:limit]
    human_readable = create_incidents_human_readable('List Incidents Results:', incidents_list)
    context = create_incidents_context(incidents_list)

    return_outputs(human_readable, {'ProofPointTRAP.Incident(val.id === obj.id)': context}, incidents_list)


def get_incident_command():
    """
        Retrieves a single incident from ProofPoint API
    """
    args = demisto.args()
    incident_id = args.pop('incident_id')
    fullurl = BASE_URL + f'api/incidents/{incident_id}.json'
    incident_data = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error(
            'Get incident failed. URL: {}, StatusCode: {}, Response: {}'.format(fullurl, incident_data.status_code,
                                                                                incident_data.text))

    incident_data = incident_data.json()
    human_readable = create_incidents_human_readable('Incident Results:', [incident_data])
    context = create_incidents_context([incident_data])

    return_outputs(human_readable, {'ProofPointTRAP.Incident(val.id === obj.id)': context}, incident_data)


def pass_sources_list_filter(incident, sources_list):
    """Checks weather an incident is passing the 'sources list' filter.

    Returns:
        bool. Weather the incident has passed the filter or not
    """
    if len(sources_list) == 0:
        return True

    for source in sources_list:
        if source in incident.get("event_sources"):
            return True

    return False


def pass_abuse_disposition_filter(incident, abuse_disposition_values):
    """Checks weather an incident is passing the 'abuse disposition' filter.

    Returns:
        bool. Weather the incident has passed the filter or not
    """
    if len(abuse_disposition_values) == 0:
        return True

    for incident_field in incident['incident_field_values']:
        if incident_field['name'] == "Abuse Disposition":
            if incident_field['value'] in abuse_disposition_values:
                return True

    return False


def filter_incidents(incidents_list):
    """Filters the incidents list by two existing filters.

    Returns:
        list. The filtered incidents list
    """
    filtered_incidents_list = []
    params = demisto.params()
    sources_list = argToList(params.get('event_sources'))
    abuse_disposition_values = argToList(params.get('abuse_disposition'))

    if not sources_list and not abuse_disposition_values:
        return incidents_list

    for incident in incidents_list:
        if pass_sources_list_filter(incident, sources_list):
            if pass_abuse_disposition_filter(incident, abuse_disposition_values):
                filtered_incidents_list.append(incident)

    return filtered_incidents_list


def get_incidents_request(params):
    """Perform an API request to get incidents from ProofPoint.
    Args:
        params(dict): The params of the request
    Returns:
        list. The incidents returned from the API call
    """
    fullurl = BASE_URL + 'api/incidents'
    incidents_list = requests.get(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        params=params,
        verify=VERIFY_CERTIFICATE
    )

    if incidents_list.status_code < 200 or incidents_list.status_code >= 300:
        if incidents_list.status_code == 502 or incidents_list.status_code == 504:
            return_error('The operation failed. There is a possibility you are trying to get too many incidents.\n'
                         'You may consider adding a filter argument to the command.\n'
                         'URL: {}, StatusCode: {}, Response: {}'.format(fullurl, incidents_list.status_code,
                                                                        incidents_list.text))
        else:
            return_error('The operation failed. URL: {}, StatusCode: {}, '
                         'Response: {}'.format(fullurl, incidents_list.status_code, incidents_list.text))
    return incidents_list.json()


def fetch_incidents_command():
    """
        Fetches incidents from the ProofPoint API.
    """
    integration_params = demisto.params()
    last_fetch = demisto.getLastRun().get('last_fetch', {})
    incidents_states = integration_params.get('states')
    for state in incidents_states:
        if not last_fetch.get(state):
            last_fetch[state] = FETCH_TIME

    incidents = []

    for state in incidents_states:
        request_params = {
            'created_after': last_fetch[state],
            'state': state
        }

        state_parsed_fetch = dateutil.parser.parse(last_fetch[state])

        incidents_list = get_incidents_request(request_params)
        filtered_incidents_list = filter_incidents(incidents_list)
        for incident in filtered_incidents_list:
            incident_creation_time = dateutil.parser.parse(incident['created_at'])
            if incident_creation_time > state_parsed_fetch:
                id = incident.get('id')
                inc = {
                    'name': f'ProofPoint_TRAP - ID {id}',
                    'rawJSON': json.dumps(incident),
                    'occurred': incident['created_at']
                }
                incidents.append(inc)

        if incidents:
            last_fetch_time = incidents[-1]['occurred']
            last_fetch[state] = last_fetch_time

    demisto.setLastRun({'last_fetch': last_fetch})
    demisto.info('extracted {} incidents'.format(len(incidents)))

    demisto.incidents(incidents)


def create_add_comment_human_readable(incident):
    """Creates the human readable entry for the 'add_comment_to_incident' command
    Args:
        incident (dict): The incident to parse

    Returns:
        str. The command human readable in markdown format
    """
    human_readable = []
    human_readable_headers = ['Created At', 'Incident ID', 'Details', 'Comments Summary', 'Action ID']
    incident_id = incident.get('incident_id')
    human_readable.append({
        'Created At': incident.get('created_at'),
        'Incident ID': incident_id,
        'Details': incident.get('detail'),
        'Comments Summary': incident.get('summary'),
        'Action ID': incident.get('id')
    })

    return tableToMarkdown(f'Comments added successfully to incident:{incident_id}', human_readable,
                           human_readable_headers)


def add_comment_to_incident_command():
    """
        Adds comments to an incident by incident ID
    """
    args = demisto.args()
    incident_id = args.get('incident_id')
    comments_to_add = args.get('comments')
    details = args.get('details')
    request_body = {
        "summary": comments_to_add,
        "detail": details
    }

    fullurl = BASE_URL + f'api/incidents/{incident_id}/comments.json'
    incident_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error(
            'Add comment to incident command failed. URL: {}, StatusCode: {}, '
            'Response: {}'.format(fullurl, incident_data.status_code, incident_data.text))

    incident_data = incident_data.json()
    human_readable = create_add_comment_human_readable(incident_data)
    return_outputs(human_readable,
                   {'ProofPointTRAP.IncidentComment(val.incident_id === obj.incident_id)': incident_data},
                   incident_data)


def add_user_to_incident_command():
    """
        Adds user to an incident by incident ID
    """
    args = demisto.args()
    incident_id = args.get('incident_id')
    attackers = argToList(args.get('attackers'))
    targets = argToList(args.get('targets'))
    request_body = {
        "targets": targets,
        "attackers": attackers
    }

    fullurl = BASE_URL + f'api/incidents/{incident_id}/users.json'
    incident_data = requests.post(
        fullurl,
        headers={
            'Content-Type': 'application/json',
            'Authorization': API_KEY
        },
        json=request_body,
        verify=VERIFY_CERTIFICATE
    )

    if incident_data.status_code < 200 or incident_data.status_code >= 300:
        return_error(
            'Add comment to incident command failed. URL: {}, StatusCode: {}, '
            'Response: {}'.format(fullurl, incident_data.status_code, incident_data.text))

    return_outputs(f'The user was added successfully to incident {incident_id}', {}, {})


''' EXECUTION CODE '''


def main():
    handle_proxy(demisto.params().get('proxy'))
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))

    if command == 'test-module':
        test()

    elif command == 'fetch-incidents':
        fetch_incidents_command()

    elif command == 'proofpoint-tr-get-list':
        get_list_command()

    elif command == 'proofpoint-tr-add-to-list':
        add_to_list_command()

    elif command == 'proofpoint-tr-block-ip':
        block_ip_command()

    elif command == 'proofpoint-tr-block-domain':
        block_domain_command()

    elif command == 'proofpoint-tr-block-url':
        block_url_command()

    elif command == 'proofpoint-tr-block-hash':
        block_hash_command()

    elif command == 'proofpoint-tr-delete-indicator':
        delete_indicator_command()

    elif command == 'proofpoint-tr-search-indicator':
        search_indicator_command()

    elif command == 'proofpoint-tr-list-incidents':
        list_incidents_command()

    elif command == 'proofpoint-tr-get-incident':
        get_incident_command()

    elif command == 'proofpoint-tr-add-comment-to-incident':
        add_comment_to_incident_command()

    elif command == 'proofpoint-tr-add-user-to-incident':
        add_user_to_incident_command()


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
