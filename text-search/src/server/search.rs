use tfhe::boolean::{ server_key::{ ServerKey, BinaryBooleanGates }, ciphertext::Ciphertext };

use super::crypto::{ FHEError, are_equal, bits_are_equal };

/// search an encrypted word in a set of encrypted words
pub fn search(
    server_key: &ServerKey,
    word: &[Ciphertext],
    list: &[Vec<Ciphertext>]
) -> Result<Ciphertext, FHEError> {
    // get an encryption of `false`
    println!("Getting an encryption of `false`...");
    let mut result_encrypted = server_key.not(&bits_are_equal(server_key, &word[0], &word[0]));
    println!("Done.");

    println!("Searching for the word...");
    // loop over the words in the list
    for word_from_list in list {
        // If the word has the right length, check it against `word`.
        // Otherwise, do nothing.
        if word_from_list.len() == word.len() {
            println!("  Checking word...");
            result_encrypted = server_key.or(
                &result_encrypted,
                &are_equal(server_key, &word, &word_from_list)?
            );
            println!("  Done.");
        }
    }
    println!("Done.");

    Ok(result_encrypted)
}
