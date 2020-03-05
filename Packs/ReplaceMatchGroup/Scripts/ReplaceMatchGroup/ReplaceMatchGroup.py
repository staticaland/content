import demistomock as demisto
import re


def main():
    value = demisto.args()['value']
    regex = re.compile(demisto.args()['regex'])
    replace_with = demisto.args()['replace_with']
    output = list()
    start = 0

    for match in regex.finditer(value):
        for index, _ in enumerate(match.groups()):
            end = match.start(index + 1)
            output.append(value[start:end])
            output.append(replace_with)
            start = match.end(index + 1)
    output.append(value[start:])  # Handling the tail of the string

    demisto.results(''.join(output))


if __name__ == "__builtin__" or __name__ == "builtins" or __name__ == "__main__":
    main()
