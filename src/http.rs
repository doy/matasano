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

pub fn create_query_string (params: HashMap<&str, &str>) -> String {
    fn escape (s: &str) -> String {
        s.replace("%", "%25").replace("&", "%26").replace("=", "%3D")
    }

    let mut parts = vec![];
    for (k, v) in params {
        let mut part = escape(k);
        part.push_str("=");
        part.push_str(&escape(v)[..]);
        parts.push(part);
    }
    return parts.connect("&");
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

#[test]
fn test_create_query_string () {
    let mut params = HashMap::new();
    params.insert("foo", "bar");
    params.insert("baz", "qux");
    params.insert("zap", "zazzle");
    let got = create_query_string(params);
    let expected1 = "foo=bar&baz=qux&zap=zazzle";
    let expected2 = "foo=bar&zap=zazzle&baz=qux";
    let expected3 = "baz=qux&foo=bar&zap=zazzle";
    let expected4 = "baz=qux&zap=zazzle&foo=bar";
    let expected5 = "zap=zazzle&foo=bar&baz=qux";
    let expected6 = "zap=zazzle&baz=qux&foo=bar";
    assert!(
        got == expected1 ||
        got == expected2 ||
        got == expected3 ||
        got == expected4 ||
        got == expected5 ||
        got == expected6,
        "didn't parse query string correctly: {}", got
    );
}

#[test]
fn test_create_query_string_malicious () {
    let mut params = HashMap::new();
    params.insert("email", "foo@bar.com&role=admin");
    let got = create_query_string(params);
    let expected = "email=foo@bar.com%26role%3Dadmin";
    assert_eq!(got, expected);
}
