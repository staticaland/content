import demistomock as demisto
import pytest


test_data = [
    ('[{"Sha1Hash"},{"437"},{"Sha1Hash"}]', '\{".*?"(\},\{)".*?"\}', '@@@', '[{"Sha1Hash"@@@"437"@@@"Sha1Hash"}]'),
    ('{"1"},{"2"},{"3"},{"4"}', '\{".*?"\}(,)\{".*?"\}', ':', '{"1"}:{"2"}:{"3"}:{"4"}'),
    ('this is a test, this is another test.', '.*?(,).*?(\.)', '!', 'this is a test! this is another test!'),
    ('a, b. c,.', '.*?(,|\.)', '!', 'a! b! c!!')
]


@pytest.mark.parametrize('value, regex, replace, result', test_data)
def test_main(mocker, value, regex, replace, result):
    from ReplaceMatchGroup import main
    mocker.patch.object(demisto, 'args', return_value={
        'value': value,
        'regex': regex,
        'replace_with': replace
    })
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == result
