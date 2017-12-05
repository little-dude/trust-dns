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
use std::collections::HashMap;
use std::sync::Arc as Rc;
use std::io::Cursor;

use bytes::{BufMut, BigEndian};
use error::{ProtoErrorKind, ProtoResult};

/// Encode DNS messages and resource record types.
pub struct BinEncoder<'a> {
    buffer: Cursor<&'a mut Vec<u8>>,
    // TODO, it would be cool to make this slices, but then the stored slice needs to live longer
    //  than the callee of store_pointer which isn't obvious right now.
    name_pointers: HashMap<Vec<Rc<String>>, u16>, // array of string, label, location in stream
    mode: EncodeMode,
    canonical_names: bool,
}

impl<'a> BinEncoder<'a> {
    /// Create a new encoder with the Vec to fill
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self::with_offset(buf, 0, EncodeMode::Normal)
    }

    /// Specify the mode for encoding
    ///
    /// # Arguments
    ///
    /// * `mode` - In Signing mode, it canonical forms of all data are encoded, otherwise format matches the source form
    pub fn with_mode(buf: &'a mut Vec<u8>, mode: EncodeMode) -> Self {
        Self::with_offset(buf, 0, mode)
    }

    /// Begins the encoder at the given offset
    ///
    /// This is used for pointers. If this encoder is starting at some point further in
    ///  the sequence of bytes, for the proper offset of the pointer, the offset accounts for that
    ///  by using the offset to add to the pointer location being written.
    ///
    /// # Arguments
    ///
    /// * `offset` - index at which to start writing into the buffer
    pub fn with_offset(buf: &'a mut Vec<u8>, offset: u32, mode: EncodeMode) -> Self {
        let mut cursor = Cursor::new(buf);
        cursor.set_position(offset as u64);
        BinEncoder {
            buffer: cursor,
            name_pointers: HashMap::new(),
            mode: mode,
            canonical_names: false,
        }
    }

    /// Returns a reference to the internal buffer
    pub fn into_bytes(self) -> &'a Vec<u8> {
        self.buffer.into_inner()
    }

    /// Returns the length of the buffer
    pub fn len(&self) -> usize {
        self.buffer.get_ref().len()
    }

    /// Returns `true` if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.get_ref().is_empty()
    }

    /// Returns the current offset into the buffer
    pub fn offset(&self) -> u32 {
        (self.buffer.position() & 0xffff_ffff) as u32
    }

    /// Returns the current Encoding mode
    pub fn mode(&self) -> EncodeMode {
        self.mode
    }

    /// If set to true, then names will be written into the buffer in canonical form
    pub fn set_canonical_names(&mut self, canonical_names: bool) {
        self.canonical_names = canonical_names;
    }

    /// Returns true if then encoder is writing in canonical form
    pub fn is_canonical_names(&self) -> bool {
        self.canonical_names
    }

    /// Emit one byte into the buffer
    pub fn emit(&mut self, b: u8) {
        self.emit_u8(b);
    }

    /// Stores a label pointer to an already written label
    ///
    /// The location is the current position in the buffer
    ///  implicitly, it is expected that the name will be written to the stream after the current index.
    pub fn store_label_pointer(&mut self, labels: Vec<Rc<String>>) {
        if self.buffer.position() < 0x3FFFu32 as u64 {
            // FIXME: this cast cast fail
            self.name_pointers.insert(labels, self.buffer.position() as u16); // the next char will be at the len() location
        }
    }

    /// Looks up the index of an already written label
    pub fn get_label_pointer(&self, labels: &[Rc<String>]) -> Option<u16> {
        self.name_pointers.get(labels).cloned()
    }

    /// matches description from above.
    ///
    /// ```
    /// use trust_dns_proto::serialize::binary::BinEncoder;
    ///
    /// let mut bytes: Vec<u8> = Vec::new();
    /// {
    ///   let mut encoder: BinEncoder = BinEncoder::new(&mut bytes);
    ///   encoder.emit_character_data("abc");
    /// }
    /// assert_eq!(bytes, vec![3,b'a',b'b',b'c']);
    /// ```
    pub fn emit_character_data(&mut self, char_data: &str) -> ProtoResult<()> {
        let char_bytes = char_data.as_bytes();
        if char_bytes.len() > 255 {
            return Err(ProtoErrorKind::CharacterDataTooLong(char_bytes.len()).into());
        }
        self.grow(char_bytes.len() + 1);
        self.buffer.put_u8(char_bytes.len() as u8); // safe to cast to u8 since len <= 255
        self.buffer.put_slice(char_bytes);
        Ok(())
    }

    /// Emit one byte into the buffer
    pub fn emit_u8(&mut self, data: u8) {
        self.grow(1);
        self.buffer.put_u8(data)
    }

    /// Writes a u16 in network byte order to the buffer
    pub fn emit_u16(&mut self, data: u16) {
        self.grow(2);
        self.buffer.put_u16::<BigEndian>(data)
    }

    /// Writes an i32 in network byte order to the buffer
    pub fn emit_i32(&mut self, data: i32) {
        self.grow(4);
        self.buffer.put_i32::<BigEndian>(data)
    }

    /// Writes an u32 in network byte order to the buffer
    pub fn emit_u32(&mut self, data: u32) {
        self.grow(4);
        self.buffer.put_u32::<BigEndian>(data)
    }

    /// Writes the byte slice to the stream
    pub fn emit_vec(&mut self, data: &[u8]) {
        self.grow(data.len());
        self.buffer.put_slice(data);
    }

    /// Return the remaining capacity af the underlying buffer
    fn remaining_capacity(&self) -> usize {
        self.buffer.get_ref().capacity() - self.len()
    }

    /// Grow the underlying buffer's capacity by at least 512 bytes
    fn reserve(&mut self, len: usize) {
        if len < 512 {
            self.buffer.get_mut().reserve(512)
        } else {
            self.buffer.get_mut().reserve(len)
        }
    }

    /// Grow the underlying buffer's length by the specified amount
    fn grow(&mut self, len: usize) {
        if self.remaining_capacity() < len {
            self.reserve(len)
        }
        let new_len = self.len() + len;
        self.buffer.get_mut().resize(new_len, 0);
    }

}

/// In the Verify mode there maybe some things which are encoded differently, e.g. SIG0 records
///  should not be included in the additional count and not in the encoded data when in Verify
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EncodeMode {
    /// In signing mode records are written in canonical form
    Signing,
    /// Write records in standard format
    Normal,
}
