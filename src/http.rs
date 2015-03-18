use std::collections::HashMap;

fn parse_query_string (string: &[u8]) -> HashMap<&[u8], &[u8]> {
    let mut map = HashMap::new();
    let mut offset = 0;
    let len = string.len();
    while offset < len {
        let key_start = offset;
        let key_end = key_start + string[key_start..]
            .iter()
            .take_while(|&&c| c != b'=')
            .count();
        if string[key_end] != b'=' {
            panic!("couldn't parse query string '{:?}'", string);
        }
        let key = &string[key_start..key_end];
        let value_start = key_end + 1;
        let value_end = value_start + string[value_start..]
            .iter()
            .take_while(|&&c| c != b'&')
            .count();
        let value = &string[value_start..value_end];
        map.insert(key, value);
        offset = value_end + 1;
    }

    return map;
}

#[test]
fn test_parse_query_string () {
    let got = parse_query_string(b"foo=bar&baz=qux&zap=zazzle");
    let mut expected = HashMap::new();
    expected.insert(b"foo", b"bar");
    expected.insert(b"baz", b"qux");
    expected.insert(b"zap", b"zazzle");
    assert_eq!(got, expected);
}
