import pickle
import uuid

import pandas as pd

from CommonServerPython import *


def get_incidents_list_from_file(input_entry_or_string, file_type):
    res = demisto.getFilePath(input_entry_or_string)
    if not res:
        return_error("Entry {} not found".format(input_entry_or_string))
    file_path = res['path']
    if file_type.startswith('csv'):
        return json.loads(pd.read_csv(file_path).fillna('').to_json(orient='records'))
    if file_type.startswith('tsv'):
        return json.loads(pd.read_csv(file_path, sep='\t').fillna('').to_json(orient='records'))
    elif file_type.startswith('json'):
        return json.loads(file_path)
    elif file_type.startswith('pickle'):
        return pd.read_pickle(file_path, compression=None)
    else:
        return_error("Unsupported file type %s" % file_type)


def main():
    # fetch query
    incident_list = get_incidents_list_from_file(demisto.args().get('fileID'),
                                                 demisto.args().get('inputType'))
    if 'limit' in demisto.args():
        try:
            incident_list = incident_list[:int(demisto.args()['limit'])]
        except ValueError:
            return_error('limit must be an int represents the number of top incidents to fetch from the file')
    # output
    file_name = str(uuid.uuid4())
    output_format = demisto.args()['outputFormat']
    if output_format == 'pickle':
        data_encoded = pickle.dumps(incident_list)
    elif output_format == 'json':
        data_encoded = json.dumps(incident_list)
    else:
        return_error("Invalid output format: %s" % output_format)
    entry = fileResult(file_name, data_encoded)
    entry['Contents'] = incident_list
    entry['HumanReadable'] = "Fetched %d incidents successfully from the file" % (len(incident_list))
    entry['EntryContext'] = {
        'GetIncidentsFromFile': {
            'Filename': file_name,
            'FileFormat': output_format,
        }
    }
    return entry


if __name__ in ['__builtin__', '__main__']:
    entry = main()
    demisto.results(entry)
