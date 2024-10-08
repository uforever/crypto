use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::Bit::{self, One, Zero};
use crate::enums::BlockSize;

mod des_decrypt;
mod des_encrypt;
mod triple_des_decrypt;
mod triple_des_encrypt;

pub use des_decrypt::DesDecrypt;
pub use des_encrypt::DesEncrypt;
pub use triple_des_decrypt::TripleDesDecrypt;
pub use triple_des_encrypt::TripleDesEncrypt;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

// initial permutation
const IP: [usize; 64] = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
    55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52,
    44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
];

// final permutation
const FP: [usize; 64] = [
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
];

const E: [usize; 48] = [
    31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17,
    18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
];

const P: [usize; 32] = [
    15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12,
    29, 5, 21, 10, 3, 24,
];

// key permuted choice
const KEY_PC: [[usize; 48]; 16] = [
    [
        9, 50, 33, 59, 48, 16, 32, 56, 1, 8, 18, 41, 2, 34, 25, 24, 43, 57, 58, 0, 35, 26, 17, 40,
        21, 27, 38, 53, 36, 3, 46, 29, 4, 52, 22, 28, 60, 20, 37, 62, 14, 19, 44, 13, 12, 61, 54,
        30,
    ],
    [
        1, 42, 25, 51, 40, 8, 24, 48, 58, 0, 10, 33, 59, 26, 17, 16, 35, 49, 50, 57, 56, 18, 9, 32,
        13, 19, 30, 45, 28, 62, 38, 21, 27, 44, 14, 20, 52, 12, 29, 54, 6, 11, 36, 5, 4, 53, 46,
        22,
    ],
    [
        50, 26, 9, 35, 24, 57, 8, 32, 42, 49, 59, 17, 43, 10, 1, 0, 48, 33, 34, 41, 40, 2, 58, 16,
        60, 3, 14, 29, 12, 46, 22, 5, 11, 28, 61, 4, 36, 27, 13, 38, 53, 62, 20, 52, 19, 37, 30, 6,
    ],
    [
        34, 10, 58, 48, 8, 41, 57, 16, 26, 33, 43, 1, 56, 59, 50, 49, 32, 17, 18, 25, 24, 51, 42,
        0, 44, 54, 61, 13, 27, 30, 6, 52, 62, 12, 45, 19, 20, 11, 60, 22, 37, 46, 4, 36, 3, 21, 14,
        53,
    ],
    [
        18, 59, 42, 32, 57, 25, 41, 0, 10, 17, 56, 50, 40, 43, 34, 33, 16, 1, 2, 9, 8, 35, 26, 49,
        28, 38, 45, 60, 11, 14, 53, 36, 46, 27, 29, 3, 4, 62, 44, 6, 21, 30, 19, 20, 54, 5, 61, 37,
    ],
    [
        2, 43, 26, 16, 41, 9, 25, 49, 59, 1, 40, 34, 24, 56, 18, 17, 0, 50, 51, 58, 57, 48, 10, 33,
        12, 22, 29, 44, 62, 61, 37, 20, 30, 11, 13, 54, 19, 46, 28, 53, 5, 14, 3, 4, 38, 52, 45,
        21,
    ],
    [
        51, 56, 10, 0, 25, 58, 9, 33, 43, 50, 24, 18, 8, 40, 2, 1, 49, 34, 35, 42, 41, 32, 59, 17,
        27, 6, 13, 28, 46, 45, 21, 4, 14, 62, 60, 38, 3, 30, 12, 37, 52, 61, 54, 19, 22, 36, 29, 5,
    ],
    [
        35, 40, 59, 49, 9, 42, 58, 17, 56, 34, 8, 2, 57, 24, 51, 50, 33, 18, 48, 26, 25, 16, 43, 1,
        11, 53, 60, 12, 30, 29, 5, 19, 61, 46, 44, 22, 54, 14, 27, 21, 36, 45, 38, 3, 6, 20, 13,
        52,
    ],
    [
        56, 32, 51, 41, 1, 34, 50, 9, 48, 26, 0, 59, 49, 16, 43, 42, 25, 10, 40, 18, 17, 8, 35, 58,
        3, 45, 52, 4, 22, 21, 60, 11, 53, 38, 36, 14, 46, 6, 19, 13, 28, 37, 30, 62, 61, 12, 5, 44,
    ],
    [
        40, 16, 35, 25, 50, 18, 34, 58, 32, 10, 49, 43, 33, 0, 56, 26, 9, 59, 24, 2, 1, 57, 48, 42,
        54, 29, 36, 19, 6, 5, 44, 62, 37, 22, 20, 61, 30, 53, 3, 60, 12, 21, 14, 46, 45, 27, 52,
        28,
    ],
    [
        24, 0, 48, 9, 34, 2, 18, 42, 16, 59, 33, 56, 17, 49, 40, 10, 58, 43, 8, 51, 50, 41, 32, 26,
        38, 13, 20, 3, 53, 52, 28, 46, 21, 6, 4, 45, 14, 37, 54, 44, 27, 5, 61, 30, 29, 11, 36, 12,
    ],
    [
        8, 49, 32, 58, 18, 51, 2, 26, 0, 43, 17, 40, 1, 33, 24, 59, 42, 56, 57, 35, 34, 25, 16, 10,
        22, 60, 4, 54, 37, 36, 12, 30, 5, 53, 19, 29, 61, 21, 38, 28, 11, 52, 45, 14, 13, 62, 20,
        27,
    ],
    [
        57, 33, 16, 42, 2, 35, 51, 10, 49, 56, 1, 24, 50, 17, 8, 43, 26, 40, 41, 48, 18, 9, 0, 59,
        6, 44, 19, 38, 21, 20, 27, 14, 52, 37, 3, 13, 45, 5, 22, 12, 62, 36, 29, 61, 60, 46, 4, 11,
    ],
    [
        41, 17, 0, 26, 51, 48, 35, 59, 33, 40, 50, 8, 34, 1, 57, 56, 10, 24, 25, 32, 2, 58, 49, 43,
        53, 28, 3, 22, 5, 4, 11, 61, 36, 21, 54, 60, 29, 52, 6, 27, 46, 20, 13, 45, 44, 30, 19, 62,
    ],
    [
        25, 1, 49, 10, 35, 32, 48, 43, 17, 24, 34, 57, 18, 50, 41, 40, 59, 8, 9, 16, 51, 42, 33,
        56, 37, 12, 54, 6, 52, 19, 62, 45, 20, 5, 38, 44, 13, 36, 53, 11, 30, 4, 60, 29, 28, 14, 3,
        46,
    ],
    [
        17, 58, 41, 2, 56, 24, 40, 35, 9, 16, 26, 49, 10, 42, 33, 32, 51, 0, 1, 8, 43, 34, 25, 48,
        29, 4, 46, 61, 44, 11, 54, 37, 12, 60, 30, 36, 5, 28, 45, 3, 22, 27, 52, 21, 20, 6, 62, 38,
    ],
];

const S_BOXES: [[[Bit; 4]; 64]; 8] = [
    [
        [One, One, One, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, One],
        [One, One, Zero, One],
        [Zero, One, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, One, Zero],
        [One, One, One, Zero],
        [One, One, One, One],
        [Zero, Zero, One, Zero],
        [One, Zero, One, One],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, One],
        [One, Zero, One, Zero],
        [One, Zero, One, Zero],
        [Zero, One, One, Zero],
        [Zero, One, One, Zero],
        [One, One, Zero, Zero],
        [One, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, One, Zero, One],
        [One, Zero, Zero, One],
        [One, Zero, Zero, One],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, One, One],
        [Zero, One, One, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, One],
        [Zero, Zero, Zero, One],
        [One, One, Zero, Zero],
        [One, One, One, Zero],
        [One, Zero, Zero, Zero],
        [One, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [One, One, Zero, One],
        [Zero, One, Zero, Zero],
        [Zero, One, One, Zero],
        [One, Zero, Zero, One],
        [Zero, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [One, Zero, One, One],
        [Zero, One, One, One],
        [One, One, One, One],
        [Zero, One, Zero, One],
        [One, One, Zero, Zero],
        [One, Zero, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, One, One],
        [Zero, One, One, One],
        [One, One, One, Zero],
        [Zero, Zero, One, One],
        [One, Zero, One, Zero],
        [One, Zero, One, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [Zero, One, One, Zero],
        [Zero, Zero, Zero, Zero],
        [One, One, Zero, One],
    ],
    [
        [One, One, One, One],
        [Zero, Zero, One, One],
        [Zero, Zero, Zero, One],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [Zero, One, One, One],
        [Zero, One, One, Zero],
        [One, One, One, One],
        [One, Zero, One, One],
        [Zero, Zero, One, Zero],
        [Zero, Zero, One, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [One, Zero, Zero, One],
        [One, One, Zero, Zero],
        [Zero, One, One, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, One],
        [One, Zero, One, Zero],
        [One, One, Zero, Zero],
        [Zero, One, One, Zero],
        [Zero, Zero, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, One, Zero, One],
        [One, Zero, One, One],
        [One, Zero, One, Zero],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, One, Zero, One],
        [One, One, One, Zero],
        [One, Zero, Zero, Zero],
        [Zero, One, One, One],
        [One, Zero, One, Zero],
        [One, Zero, One, One],
        [Zero, Zero, Zero, One],
        [One, Zero, One, Zero],
        [Zero, Zero, One, One],
        [Zero, One, Zero, Zero],
        [One, One, One, One],
        [One, One, Zero, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, Zero],
        [Zero, One, Zero, One],
        [One, Zero, One, One],
        [One, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, One, Zero, Zero],
        [Zero, One, One, One],
        [Zero, One, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, One, One],
        [Zero, One, Zero, One],
        [Zero, Zero, One, Zero],
        [One, One, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
    ],
    [
        [One, Zero, One, Zero],
        [One, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, One, One, Zero],
        [One, Zero, Zero, One],
        [Zero, One, One, Zero],
        [Zero, Zero, One, One],
        [Zero, Zero, One, One],
        [Zero, One, Zero, Zero],
        [One, One, One, One],
        [Zero, One, One, Zero],
        [Zero, One, Zero, One],
        [One, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, Zero],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [One, One, Zero, Zero],
        [Zero, One, Zero, One],
        [Zero, One, One, One],
        [One, One, One, Zero],
        [One, Zero, One, One],
        [One, One, Zero, Zero],
        [Zero, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, Zero, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, One],
        [Zero, Zero, Zero, One],
        [Zero, One, One, Zero],
        [One, Zero, One, Zero],
        [Zero, One, Zero, Zero],
        [One, One, Zero, One],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, One, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, One],
        [One, Zero, One, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, Zero, One],
        [One, One, One, One],
        [Zero, Zero, One, Zero],
        [One, One, One, Zero],
        [One, One, Zero, Zero],
        [Zero, Zero, One, One],
        [Zero, One, Zero, One],
        [One, Zero, One, One],
        [One, Zero, One, Zero],
        [Zero, One, Zero, One],
        [One, One, One, Zero],
        [Zero, Zero, One, Zero],
        [Zero, One, One, One],
        [One, One, Zero, Zero],
    ],
    [
        [Zero, One, One, One],
        [One, One, Zero, One],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [One, One, One, Zero],
        [One, Zero, One, One],
        [Zero, Zero, One, One],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [Zero, One, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, Zero, One, Zero],
        [Zero, Zero, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, One, One, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, One, Zero, One],
        [One, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, Zero, Zero, One],
        [One, One, Zero, Zero],
        [One, Zero, One, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
        [One, Zero, One, Zero],
        [Zero, Zero, One, One],
        [Zero, One, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, One, Zero],
        [One, Zero, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, One, One],
        [One, One, Zero, One],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [One, One, One, One],
        [One, Zero, Zero, One],
        [Zero, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, One, One],
        [Zero, One, Zero, One],
        [One, One, One, Zero],
        [One, Zero, One, One],
        [Zero, One, Zero, One],
        [One, One, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, One, One, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
    ],
    [
        [Zero, Zero, One, Zero],
        [One, One, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, Zero],
        [Zero, One, One, One],
        [Zero, One, Zero, Zero],
        [One, Zero, One, Zero],
        [Zero, One, One, One],
        [One, Zero, One, One],
        [One, One, Zero, One],
        [Zero, One, One, Zero],
        [Zero, Zero, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, One, One],
        [One, One, One, One],
        [One, One, One, One],
        [One, Zero, One, Zero],
        [One, One, Zero, One],
        [Zero, Zero, One, One],
        [Zero, Zero, Zero, Zero],
        [One, Zero, Zero, One],
        [One, One, One, Zero],
        [One, Zero, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, One, One, Zero],
        [Zero, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, Zero, One, Zero],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, Zero],
        [One, Zero, One, One],
        [Zero, One, One, One],
        [One, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, One],
        [One, One, One, Zero],
        [Zero, One, One, One],
        [Zero, Zero, One, Zero],
        [One, Zero, Zero, Zero],
        [One, One, Zero, One],
        [One, One, One, One],
        [Zero, One, One, Zero],
        [One, Zero, Zero, One],
        [One, One, One, One],
        [One, One, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [One, Zero, Zero, One],
        [Zero, One, One, Zero],
        [One, Zero, One, Zero],
        [Zero, Zero, One, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [One, One, One, Zero],
        [Zero, Zero, One, One],
    ],
    [
        [One, One, Zero, Zero],
        [One, Zero, One, Zero],
        [Zero, Zero, Zero, One],
        [One, One, One, One],
        [One, Zero, One, Zero],
        [Zero, One, Zero, Zero],
        [One, One, One, One],
        [Zero, Zero, One, Zero],
        [One, Zero, Zero, One],
        [Zero, One, One, One],
        [Zero, Zero, One, Zero],
        [One, One, Zero, Zero],
        [Zero, One, One, Zero],
        [One, Zero, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, One, Zero, One],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, One],
        [One, One, Zero, One],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [One, One, One, Zero],
        [Zero, Zero, Zero, Zero],
        [Zero, One, One, One],
        [One, Zero, One, One],
        [Zero, One, Zero, One],
        [Zero, Zero, One, One],
        [One, Zero, One, One],
        [One, Zero, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [Zero, Zero, One, One],
        [One, One, One, One],
        [Zero, Zero, One, Zero],
        [Zero, One, Zero, One],
        [One, One, Zero, Zero],
        [Zero, Zero, One, Zero],
        [One, Zero, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, One, Zero, One],
        [One, One, Zero, Zero],
        [One, One, One, One],
        [Zero, Zero, One, One],
        [One, Zero, One, Zero],
        [Zero, One, One, One],
        [One, Zero, One, One],
        [Zero, Zero, Zero, Zero],
        [One, One, One, Zero],
        [Zero, One, Zero, Zero],
        [Zero, Zero, Zero, One],
        [One, Zero, One, Zero],
        [Zero, One, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, One, Zero],
        [One, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, Zero, One, One],
        [One, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, One, Zero, One],
    ],
    [
        [Zero, One, Zero, Zero],
        [One, One, Zero, One],
        [One, Zero, One, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [One, Zero, One, One],
        [One, One, One, Zero],
        [Zero, One, One, One],
        [One, One, One, One],
        [Zero, One, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [One, Zero, Zero, One],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, One],
        [One, One, Zero, One],
        [One, Zero, One, Zero],
        [Zero, Zero, One, One],
        [One, One, One, Zero],
        [One, One, Zero, Zero],
        [Zero, Zero, One, One],
        [One, Zero, Zero, One],
        [Zero, One, Zero, One],
        [Zero, One, One, One],
        [One, One, Zero, Zero],
        [Zero, One, Zero, One],
        [Zero, Zero, One, Zero],
        [One, Zero, One, Zero],
        [One, One, One, One],
        [Zero, One, One, Zero],
        [One, Zero, Zero, Zero],
        [Zero, Zero, Zero, One],
        [Zero, One, One, Zero],
        [Zero, Zero, Zero, One],
        [Zero, One, One, Zero],
        [Zero, One, Zero, Zero],
        [One, Zero, One, One],
        [One, Zero, One, One],
        [One, One, Zero, One],
        [One, One, Zero, One],
        [One, Zero, Zero, Zero],
        [One, One, Zero, Zero],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, One],
        [Zero, One, Zero, Zero],
        [Zero, One, One, One],
        [One, Zero, One, Zero],
        [One, One, One, Zero],
        [Zero, One, One, One],
        [One, Zero, One, Zero],
        [One, Zero, Zero, One],
        [One, One, One, One],
        [Zero, One, Zero, One],
        [Zero, One, One, Zero],
        [Zero, Zero, Zero, Zero],
        [One, Zero, Zero, Zero],
        [One, One, One, One],
        [Zero, Zero, Zero, Zero],
        [One, One, One, Zero],
        [Zero, One, Zero, One],
        [Zero, Zero, One, Zero],
        [One, Zero, Zero, One],
        [Zero, Zero, One, One],
        [Zero, Zero, One, Zero],
        [One, One, Zero, Zero],
    ],
    [
        [One, One, Zero, One],
        [Zero, Zero, Zero, One],
        [Zero, Zero, One, Zero],
        [One, One, One, One],
        [One, Zero, Zero, Zero],
        [One, One, Zero, One],
        [Zero, One, Zero, Zero],
        [One, Zero, Zero, Zero],
        [Zero, One, One, Zero],
        [One, Zero, One, Zero],
        [One, One, One, One],
        [Zero, Zero, One, One],
        [One, Zero, One, One],
        [Zero, One, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [One, Zero, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, One, Zero, One],
        [Zero, Zero, One, One],
        [Zero, One, One, Zero],
        [One, One, One, Zero],
        [One, Zero, One, One],
        [Zero, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [Zero, Zero, Zero, Zero],
        [One, One, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, Zero, One],
        [Zero, One, One, One],
        [Zero, Zero, One, Zero],
        [Zero, One, One, One],
        [Zero, Zero, One, Zero],
        [One, Zero, One, One],
        [Zero, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [One, One, One, Zero],
        [Zero, Zero, Zero, One],
        [Zero, One, One, One],
        [One, Zero, Zero, One],
        [Zero, One, Zero, Zero],
        [One, One, Zero, Zero],
        [One, Zero, One, Zero],
        [One, One, One, Zero],
        [One, Zero, Zero, Zero],
        [Zero, Zero, One, Zero],
        [One, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, One, One, One],
        [Zero, One, One, Zero],
        [One, One, Zero, Zero],
        [One, Zero, One, Zero],
        [One, Zero, Zero, One],
        [One, One, Zero, One],
        [Zero, Zero, Zero, Zero],
        [One, One, One, One],
        [Zero, Zero, One, One],
        [Zero, Zero, One, One],
        [Zero, One, Zero, One],
        [Zero, One, Zero, One],
        [Zero, One, One, Zero],
        [One, Zero, Zero, Zero],
        [One, Zero, One, One],
    ],
];

// 密钥调度
fn key_schedule(key: &Bytes) -> Vec<Bits> {
    // 取有效位 56 bit
    // PC1: 64bit -> 56bit
    // 通过分成左右两部分
    // 分别循环左移 再通过PC2生成16个48bit的key
    // PC2: 56bit -> 48bit * 16
    // 我这里直接合并了两次置换选择
    let original_key: Bits = key.to_bits();

    let mut sub_keys = Vec::with_capacity(16);
    for pc in &KEY_PC {
        sub_keys.push(original_key.permutation(pc));
    }

    sub_keys
}

// 替换 48bit -> 32bit
fn s_boxes(input: &Bits) -> Bits {
    let mut result = vec![];

    for (box_index, chunk) in input.chunks(6).enumerate() {
        // bits to uzise
        let bits = Bits::new(chunk);
        let s_box = S_BOXES[box_index];

        let substituted_bits = bits.substitution(s_box);
        result.extend_from_slice(&substituted_bits);
    }
    Bits::new(result)
}

fn block_crypt(sub_keys: &[Bits]) -> impl Fn(&[Bit]) -> Bits + '_ {
    move |block: &[Bit]| -> Bits {
        // initial permutation
        let permuted_block = Bits::new(block).permutation(&IP);

        let mut left = Bits::new(&permuted_block[0..32]);
        let mut right = Bits::new(&permuted_block[32..]);

        for sub_key in sub_keys {
            // expand 32bit -> 48bit
            let expanded_right = right.permutation(&E);
            // xor with subkey
            let xor_result = expanded_right.xor(sub_key);

            // substitute 48bit -> 32bit
            let substituted_result = s_boxes(&xor_result);
            // 32bit -> 32bit permutation
            let permuted_result = substituted_result.permutation(&P);

            // xor with left
            let new_right = permuted_result.xor(&left);
            left = right;
            right = new_right;
        }

        let final_bits: Bits = Bits::new([right.to_vec(), left.to_vec()].concat());
        // final permutation
        final_bits.permutation(&FP)
    }
}
