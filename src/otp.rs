use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::{
    fmt::{self, Display},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct OtpGenerator {
    secret_bytes: Vec<u8>,
    interval: u64,
    nr_digits: u8,
}

pub struct OtpCode {
    value: u32,
    validity_sec: u64,
    nr_digits: u8,
}

impl OtpCode {
    fn new(value: u32, validity_sec: u64, nr_digits: u8) -> Self {
        OtpCode {
            value,
            validity_sec,
            nr_digits,
        }
    }
}

impl Display for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            format!(
                "{:0>dgts$} (Validity: {}s)",
                self.value,
                self.validity_sec,
                dgts = self.nr_digits as usize
            )
        )
    }
}

impl OtpGenerator {
    pub fn new(secret_bytes: &[u8], interval: u64, nr_digits: u8) -> Self {
        OtpGenerator {
            secret_bytes: secret_bytes.to_vec(),
            interval,
            nr_digits,
        }
    }

    /* RFC4226 section 5.4 */
    fn dt(hmac_output: &[u8]) -> u32 {
        let offset_bits = (hmac_output[19] & 0xf) as usize;
        (hmac_output[offset_bits] as u32 & 0x7f) << 24
            | (hmac_output[offset_bits + 1] as u32 & 0xff) << 16
            | (hmac_output[offset_bits + 2] as u32 & 0xff) << 8
            | (hmac_output[offset_bits + 3] as u32 & 0xff)
    }

    fn get_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to compute the timestamp")
            .as_secs()
    }

    fn time_to_next_generation(&self) -> u64 {
        self.interval - (Self::get_time() % self.interval)
    }

    pub fn generate(&self) -> Result<OtpCode, ()> {
        let time = Self::get_time();
        let counter = time / self.interval;

        // Compute HOTP(secret, counter)
        let mut hmac = Hmac::<Sha1>::new_from_slice(&self.secret_bytes).map_err(|_| ())?;
        hmac.update(&counter.to_be_bytes());
        let hmac_result = hmac.finalize().into_bytes();

        let sbits = Self::dt(&hmac_result);
        let result = sbits % (10_u32.pow(self.nr_digits as u32));
        Ok(OtpCode::new(
            result,
            self.time_to_next_generation(),
            self.nr_digits,
        ))
    }
}
