use std::collections::HashMap;

pub fn parse_query_string (string: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    let mut offset = 0;
    let len = string.as_bytes().len();
    while offset < len {
        let key_start = offset;
        let key_end = key_start + string[key_start..]
            .find('=')
            .unwrap_or_else(|| {
                panic!("couldn't parse query string '{:?}'", string)
            });
        let key = &string[key_start..key_end];
        let value_start = key_end + 1;
        let value_end = value_start + string[value_start..]
            .find('&')
            .unwrap_or_else(|| string[value_start..].as_bytes().len());
        let value = &string[value_start..value_end];
        map.insert(key, value);
        offset = value_end + 1;
    }

    return map;
}

#[test]
fn test_parse_query_string () {
    let got = parse_query_string("foo=bar&baz=qux&zap=zazzle");
    let mut expected = HashMap::new();
    expected.insert("foo", "bar");
    expected.insert("baz", "qux");
    expected.insert("zap", "zazzle");
    assert_eq!(got, expected);
}
