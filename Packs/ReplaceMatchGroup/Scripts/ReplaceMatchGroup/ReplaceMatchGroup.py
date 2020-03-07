import demistomock as demisto
from CommonServerPython import DemistoException
import re


def main(args):
    value = args['value']
    replace_with = args['replace_with']
    output = list()
    start = 0
    compile_err_msg: str = 'Could not compile regex.'

    try:
        regex = re.compile(args['regex'])
    except re.error:
        raise DemistoException(compile_err_msg)
    except TypeError:
        raise DemistoException(compile_err_msg)

    for match in regex.finditer(value):
        for index, _ in enumerate(match.groups(), start=1):
            end = match.start(index)
            output.append(value[start:end])
            output.append(replace_with)
            start = match.end(index)
    output.append(value[start:])  # Handling the tail of the string

    return ''.join(output)


if __name__ in ["__builtin__", "builtins", "__main__"]:
    result = main(demisto.args())
    demisto.results(result)
