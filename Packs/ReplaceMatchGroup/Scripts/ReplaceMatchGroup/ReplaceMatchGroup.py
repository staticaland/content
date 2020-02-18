import demistomock as demisto
import re


def main():
    value = demisto.args()['value']
    regex = demisto.args()['regex']
    replace_with = demisto.args()['replaceWith']

    to_replace_list: list = re.findall(regex, value)
    for item in to_replace_list:
        if isinstance(item, tuple):
            item_list = list(item)
            for sub_item in item_list:
                value = value.replace(sub_item, replace_with)
        elif isinstance(item, str):
            value = value.replace(item, replace_with)
    demisto.results(value)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
