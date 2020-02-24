import pickle
import uuid

import pandas as pd

from CommonServerPython import *
from GetIncidentsFromFile import main

INPUT_FILE_PATH = './TestData/input_json_file_test'
INPUT_FILE_FORMAT = 'csv'
OUTPUT_FILENAME = './TestData/output'
TEMP = 'temp'


def test_get_incidetns_from_file(mocker):
    input_args = {'fileID': 'SOME_FILE_ID',
                  'inputType': INPUT_FILE_FORMAT,
                  'limit': 1000,
                  'outputFormat': 'pickle'}
    mocker.patch.object(demisto, 'args', return_value=input_args)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': INPUT_FILE_PATH})
    mocker.patch.object(demisto, 'investigation', return_value={'id': OUTPUT_FILENAME})
    mocker.patch.object(demisto, 'uniqueFile', return_value=TEMP)
    mocker.patch.object(uuid, 'uuid4', return_value='output_file_name')

    main()
    with open(OUTPUT_FILENAME + '_' + TEMP, 'rb') as f:
        output_incidents = pickle.load(f)
    input_incidents = json.loads(pd.read_csv(INPUT_FILE_PATH).fillna('').to_json(orient='records'))
    for input_i, output_i in zip(input_incidents, output_incidents):
        for k in input_i:
            assert input_i[k] == output_i[k]
        for k in output_i:
            assert input_i[k] == output_i[k]


def test_get_incidetns_from_file_with_limit(mocker):
    limit = 2
    input_args = {'fileID': 'SOME_FILE_ID',
                  'inputType': INPUT_FILE_FORMAT,
                  'limit': limit,
                  'outputFormat': 'pickle'}
    mocker.patch.object(demisto, 'args', return_value=input_args)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': INPUT_FILE_PATH})
    mocker.patch.object(demisto, 'investigation', return_value={'id': OUTPUT_FILENAME})
    mocker.patch.object(demisto, 'uniqueFile', return_value=TEMP)
    mocker.patch.object(uuid, 'uuid4', return_value='output_file_name')

    main()
    with open(OUTPUT_FILENAME + '_' + TEMP, 'rb') as f:
        output_incidents = pickle.load(f)
    assert len(output_incidents) == limit
