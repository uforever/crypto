use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug, Default)]
pub struct RC4 {
    passphrase: Bytes,
}

impl RC4 {
    pub fn new(passphrase: Bytes) -> Self {
        Self { passphrase }
    }
}

const ZERO_S_BOX: [u8; 256] = [
    0, 35, 3, 43, 9, 11, 65, 229, 32, 36, 134, 98, 59, 34, 173, 153, 214, 200, 64, 161, 191, 62, 6,
    25, 56, 234, 49, 246, 69, 133, 203, 194, 10, 42, 228, 198, 195, 245, 236, 91, 206, 23, 235, 27,
    138, 18, 143, 250, 244, 76, 123, 217, 132, 249, 72, 127, 94, 151, 33, 60, 248, 85, 177, 210,
    142, 83, 110, 140, 41, 135, 196, 238, 156, 242, 141, 67, 5, 185, 131, 63, 137, 37, 172, 121,
    70, 144, 237, 130, 17, 44, 253, 166, 78, 201, 12, 119, 215, 7, 126, 114, 97, 192, 53, 4, 254,
    45, 102, 122, 230, 88, 193, 129, 160, 124, 84, 108, 239, 189, 152, 120, 115, 207, 50, 176, 86,
    157, 164, 187, 71, 1, 15, 58, 29, 21, 46, 145, 247, 162, 95, 183, 13, 226, 159, 175, 221, 100,
    96, 202, 101, 178, 154, 47, 205, 106, 148, 104, 93, 112, 26, 165, 128, 186, 146, 218, 66, 211,
    171, 90, 252, 19, 40, 99, 223, 174, 255, 51, 77, 227, 48, 220, 168, 118, 224, 103, 75, 105,
    125, 199, 73, 82, 57, 181, 81, 149, 68, 52, 232, 22, 2, 216, 113, 30, 109, 163, 92, 61, 14, 8,
    38, 225, 79, 231, 170, 240, 20, 219, 204, 150, 180, 188, 116, 190, 241, 197, 179, 87, 74, 147,
    80, 54, 212, 16, 167, 222, 136, 213, 55, 182, 139, 24, 209, 251, 208, 28, 111, 89, 158, 155,
    243, 107, 233, 169, 117, 184, 31, 39,
];

// 密钥调度算法KSA
fn ksa(key: &[u8]) -> [u8; 256] {
    let key_length = key.len();
    if key_length == 0 {
        return ZERO_S_BOX;
    }
    let mut s_box: [u8; 256] = std::array::from_fn(|i| i as u8);

    let mut j: usize = 0;
    (0..256).for_each(|i| {
        j = (j + s_box[i] as usize + key[i % key_length] as usize) % 256;
        s_box.swap(i, j);
    });

    s_box
}

impl Operation for RC4 {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let mut s_box = ksa(&self.passphrase);

        // 伪随机生成算法PRGA
        let mut j: usize = 0;
        let output: Vec<u8> = input
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                let i = (index + 1) % 256;
                j = (j + s_box[i] as usize) % 256;
                s_box.swap(i, j);
                let k = s_box[(s_box[i] as usize + s_box[j] as usize) % 256];
                byte ^ k
            })
            .collect();

        Ok(Bytes::new(output))
    }
}
