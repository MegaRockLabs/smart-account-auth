pub fn base64_to_url(b64: &str) -> String {
    b64.replace("+", "-").replace("/", "_").replace("=", "")
}


pub fn url_to_base64(url: &str) -> String {
    let mut b64 = url.replace("-", "+").replace("_", "/");
    let len = b64.len();
    if len % 4 != 0 {
        b64.push_str(&"=".repeat(4 - len % 4));
    }
    b64
}

