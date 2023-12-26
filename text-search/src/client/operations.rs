use tfhe::{ boolean::client_key::ClientKey, boolean::ciphertext::Ciphertext };

pub const N_BITS_PER_CHAR: usize = 8;

pub fn str_to_encrypted_seq(client_key: &ClientKey, plaintext: &str) -> Vec<Ciphertext> {
    // convert the string to a sequence of bytes
    let plaintext_bytes = plaintext.as_bytes();

    // create a vector of ciphertexts
    let mut result = Vec::<Ciphertext>::new();

    // compute encrypted true and encrypted false values once
    let enc_true = client_key.encrypt(true);
    let enc_false = client_key.encrypt(false);

    // loop over the bytes of the plaintext
    for x in plaintext_bytes {
        // loop over the bits of the current byte
        for i in 0..N_BITS_PER_CHAR {
            // if the bit is 1, push an encryption of true to the results
            // otherwise, push an encryption of false
            if (*x & (1 << i)) != 0 {
                result.push(enc_true.clone());
            } else {
                result.push(enc_false.clone());
            }
        }
    }

    return result;
}

/// split a string on spaces and pad the words with ` `
pub fn split_and_pad_str(text: &str, length: usize) -> Vec<String> {
    text.split(' ')
        .map(|x| { format!("{:*<1$}", x, length) })
        .collect()
}

/// pad `word` with ` ` up to length `length`
pub fn pad_word(word: &str, length: usize) -> String {
    format!("{:*<1$}", word, length)
}
