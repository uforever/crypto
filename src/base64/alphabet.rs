#[derive(Debug)]
pub struct Alphabet {
    pub charset: [u8; 64],
    pub padding: Option<u8>,
}

pub const STANDARD: Alphabet = Alphabet {
    charset: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    padding: Some(b'='),
};

pub const URL_SAFE: Alphabet = Alphabet {
    charset: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    padding: None,
};

pub const FILENAME_SAFE: Alphabet = Alphabet {
    charset: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
    padding: Some(b'='),
};

pub const ITOA64: Alphabet = Alphabet {
    charset: *b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    padding: Some(b'='),
};

pub const XML: Alphabet = Alphabet {
    charset: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.",
    padding: None,
};

pub const Y64: Alphabet = Alphabet {
    charset: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._",
    padding: Some(b'-'),
};

pub const Z64: Alphabet = Alphabet {
    charset: *b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/",
    padding: Some(b'='),
};

pub const RADIX64: Alphabet = Alphabet {
    charset: *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
    padding: Some(b'='),
};

pub const XXENCODING: Alphabet = Alphabet {
    charset: *b"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    padding: None,
};

pub const BIN_HEX: Alphabet = Alphabet {
    charset: *b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr",
    padding: None,
};

pub const ROT13: Alphabet = Alphabet {
    charset: *b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/",
    padding: Some(b'='),
};

pub const UNIX_CRYPT: Alphabet = Alphabet {
    charset: *b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    padding: None,
};

pub const ATOM128: Alphabet = Alphabet {
    charset: *b"/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdE",
    padding: Some(b'C'),
};

pub const MEGAN35: Alphabet = Alphabet {
    charset: *b"3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF",
    padding: Some(b'5'),
};

pub const ZONG22: Alphabet = Alphabet {
    charset: *b"ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt",
    padding: Some(b'2'),
};

pub const HAZZ15: Alphabet = Alphabet {
    charset: *b"HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC",
    padding: Some(b'5'),
};

impl Default for Alphabet {
    fn default() -> Self {
        STANDARD
    }
}

impl Alphabet {
    pub fn new(charset: [u8; 64], padding: Option<u8>) -> Self {
        Self { charset, padding }
    }
}
