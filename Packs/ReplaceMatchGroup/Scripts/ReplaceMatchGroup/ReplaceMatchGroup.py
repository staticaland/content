import demistomock as demisto
import re


def main(args):
    value = args['value']
    regex = re.compile(args['regex'])
    replace_with = args['replace_with']
    output = list()
    start = 0

    for match in regex.finditer(value):
        for index, _ in enumerate(match.groups()):
            end = match.start(index + 1)
            output.append(value[start:end])
            output.append(replace_with)
            start = match.end(index + 1)
    output.append(value[start:])  # Handling the tail of the string

    return ''.join(output)


if __name__ in ["__builtin__", "builtins", "__main__"]:
    result = main(demisto.args())
    demisto.results(result)
