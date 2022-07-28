use std::io::Write;
use std::env::args;

trait EncodeForArbitrary {
    fn encode<W: Write>(self, buf: &mut W);
}

impl EncodeForArbitrary for bool {
    fn encode<W: Write>(self, buf: &mut W) {
        // Note: only the LSB is counted, i.e. any odd number is true and any even number is false

        match self {
            true => buf.write(&[0x01]).unwrap(),
            false => buf.write(&[0x00]).unwrap(),
        };
    }
}

impl<T: EncodeForArbitrary> EncodeForArbitrary for Vec<T> {
    fn encode<W: Write>(self, buf: &mut W) {
        for i in self {
            true.encode(buf);
            i.encode(buf);
        }
        false.encode(buf);
    }
}

impl EncodeForArbitrary for u64 {
    fn encode<W: Write>(self, buf: &mut W) {
        buf.write(&self.to_le_bytes()).unwrap();
    }
}
impl EncodeForArbitrary for u32 {
    fn encode<W: Write>(self, buf: &mut W) {
        buf.write(&self.to_le_bytes()).unwrap();
    }
}
impl EncodeForArbitrary for f32 {
    fn encode<W: Write>(self, buf: &mut W) {
        self.to_bits().encode(buf);
    }
}

fn main() {
    let mut buf = Vec::new();

    let fee_rate: f32 = args().nth(1).unwrap().parse().unwrap();
    let value: u64 = args().nth(2).unwrap().parse().unwrap();

    // fee_rate
    fee_rate.encode(&mut buf);
    // inputs
    vec![100_000_u64, 10, 200_000].encode(&mut buf);
    // outputs
    vec![value + 50].encode(&mut buf);

    std::io::stdout().write_all(&buf).unwrap();
}
