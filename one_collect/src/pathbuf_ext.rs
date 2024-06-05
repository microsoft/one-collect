pub trait PathBufInteger {
    fn push_u64(&mut self, value: u64);

    fn push_u32(&mut self, value: u32) {
        self.push_u64(value as u64);
    }

    fn push_u16(&mut self, value: u16) {
        self.push_u64(value as u64);
    }
}

const NUMS: &[u8; 10] = b"0123456789";

impl PathBufInteger for std::path::PathBuf {
    fn push_u64(&mut self, value: u64) {
        if value == 0 {
            self.push("0");
            return;
        }

        let mut tmp: [u8; 20] = [0; 20];
        let mut value = value;
        let mut i = 20;

        while i != 0 && value != 0 {
            i -= 1;
            tmp[i] = NUMS[(value % 10) as usize];
            value /= 10;
        }

        if let Ok(num) = std::str::from_utf8(&tmp[i..]) {
            self.push(num);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut buf = std::path::PathBuf::new();

        buf.push_u64(0);
        assert_eq!("0", buf.to_str().unwrap());

        buf.clear();
        buf.push_u64(123456789000);
        assert_eq!("123456789000", buf.to_str().unwrap());

        buf.clear();
        buf.push_u64(18446744073709551615);
        assert_eq!("18446744073709551615", buf.to_str().unwrap());
    }
}
