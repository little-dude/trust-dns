/*
 * Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::io::Cursor;
use bytes::{BigEndian, Buf};
use error::{ProtoErrorKind, ProtoResult, ProtoError};

/// This is non-destructive to the inner buffer, b/c for pointer types we need to perform a reverse
///  seek to lookup names
///
/// A note on serialization, there was a thought to have this implement the Serde deserializer,
///  but given that this is such a small subset of all the serialization which that performs
///  this is a simpler implementation without the cruft, at least for serializing to/from the
///  binary DNS protocols.
pub struct BinDecoder<'a>(Cursor<&'a [u8]>);

fn eof() -> ProtoError {
    ProtoErrorKind::Message("unexpected end of input reached").into()
}

impl<'a> BinDecoder<'a> {
    /// Creates a new BinDecoder
    ///
    /// # Arguments
    ///
    /// * `buffer` - buffer from which all data will be read
    pub fn new(buffer: &'a [u8]) -> Self {
        BinDecoder(Cursor::new(buffer))
    }

    /// Pop one byte from the buffer
    pub fn pop(&mut self) -> ProtoResult<u8> {
        self.read_u8()
    }

    /// Returns the number of bytes in the buffer
    pub fn len(&self) -> usize {
        self.0.remaining()
    }

    /// Returns `true` if the buffer is empty
    pub fn is_empty(&self) -> bool {
        !self.0.has_remaining()
    }

    /// Peed one byte forward, without moving the current index forward
    pub fn peek(&self) -> Option<u8> {
        if !self.is_empty() {
            Some(self.0.bytes()[0])
        } else {
            None
        }
    }

    /// Return the current position in the buffer
    pub fn index(&self) -> usize {
        self.0.position() as usize
    }

    /// This is a pretty efficient clone, as the buffer is never cloned, and only the index is set
    ///  to the value passed in
    pub fn clone(&self, index_at: u16) -> BinDecoder {
        let mut cursor = self.0.clone();
        cursor.set_position(index_at as u64);
        BinDecoder(cursor)
    }

    /// Reads a String from the buffer
    ///
    /// ```text
    /// <character-string> is a single
    /// length octet followed by that number of characters.  <character-string>
    /// is treated as binary information, and can be up to 256 characters in
    /// length (including the length octet).
    /// ```
    ///
    /// # Returns
    ///
    /// A String version of the character data
    pub fn read_character_data(&mut self) -> ProtoResult<String> {
        let length = self.read_u8()? as usize;
        Ok(String::from_utf8(self.read_vec(length)?)?)
    }

    /// Reads a Vec out of the buffer
    ///
    /// # Arguments
    ///
    /// * `len` - number of bytes to read from the buffer
    ///
    /// # Returns
    ///
    /// The Vec of the specified length, otherwise an error
    pub fn read_vec(&mut self, len: usize) -> ProtoResult<Vec<u8>> {
        if self.len() >= len {
            let mut buf = vec![0; len];
            self.0.copy_to_slice(&mut buf);
            Ok(buf)
        } else {
            Err(eof())
        }
    }

     /// Reads a slice out of the buffer, without allocating
     ///
     /// # Arguments
     ///
     /// * `len` - number of bytes to read from the buffer
     ///
     /// # Returns
     ///
     /// The slice of the specified length, otherwise an error
     pub fn read_slice(&mut self, len: usize) -> ProtoResult<&'a [u8]> {
         if len > self.len() {
             return Err(ProtoErrorKind::Message("buffer exhausted").into());
         } else {
             let pos = self.index();
             Ok(self.0.get_ref()[pos..pos + len].as_ref())
         }
     }

    /// Reads a byte from the buffer, equivalent to `Self::pop()`
    pub fn read_u8(&mut self) -> ProtoResult<u8> {
        if self.is_empty() {
            Err(eof())
        } else {
            Ok(self.0.get_u8())
        }
    }

    /// Reads the next 2 bytes into u16
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the u16 from the buffer
    pub fn read_u16(&mut self) -> ProtoResult<u16> {
        if self.len() <= 1 {
            Err(eof())
        } else {
            Ok(self.0.get_u16::<BigEndian>())
        }
    }

    /// Reads the next four bytes into i32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the i32 from the buffer
    pub fn read_i32(&mut self) -> ProtoResult<i32> {
        if self.len() <= 3 {
            Err(eof())
        } else {
            Ok(self.0.get_i32::<BigEndian>())
        }
    }

    /// Reads the next four bytes into u32.
    ///
    /// This performs a byte-by-byte manipulation, there
    ///  which means endianness is implicitly handled (i.e. no network to little endian (intel), issues)
    ///
    /// # Return
    ///
    /// Return the u32 from the buffer
    pub fn read_u32(&mut self) -> ProtoResult<u32> {
        if self.len() <= 3 {
            Err(eof())
        } else {
            Ok(self.0.get_u32::<BigEndian>())
        }
    }
}

#[cfg(tests)]
mod tests {
    use super::*;

    #[test]
    fn test_read_slice() {
        let deadbeef = b"deadbeef";
        let mut decoder = BinDecoder::new(deadbeef);

        let read = decoder.read_slice(4).expect("failed to read dead");
        assert_eq!(read, "dead");

        let read = decoder.read_slice(2).expect("failed to read be");
        assert_eq!(read, "be");

        let read = decoder.read_slice(0).expect("failed to read nothing");
        assert_eq!(read, "");

        // this should fail
        assert!(decoder.read_slice(3).is_err());
    }
}
