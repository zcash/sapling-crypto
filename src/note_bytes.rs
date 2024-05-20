/// Represents a fixed-size array of bytes for note components.
#[derive(Clone, Copy, Debug)]
pub struct NoteBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> AsRef<[u8]> for NoteBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for NoteBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// FIXME: consider implementing and using TryFrom instead
impl<const N: usize> From<&[u8]> for NoteBytes<N> {
    fn from(s: &[u8]) -> Self {
        Self(s.try_into().unwrap())
    }
}

impl<const N: usize> From<(&[u8], &[u8])> for NoteBytes<N> {
    fn from(s: (&[u8], &[u8])) -> Self {
        Self([s.0, s.1].concat().try_into().unwrap())
    }
}

/// Defines the ability to concatenate two byte slices.
pub trait NoteByteConcat: for<'a> From<(&'a [u8], &'a [u8])> {}

impl<const N: usize> NoteByteConcat for NoteBytes<N> {}

/// Defines the behavior for types that can provide read-only access to their internal byte array.
pub trait NoteByteReader: AsRef<[u8]> + for<'a> From<&'a [u8]> + Clone + Copy {}

impl<const N: usize> NoteByteReader for NoteBytes<N> {}

/// Defines the behavior for types that support both read and write access to their internal byte array.
pub trait NoteByteWriter: NoteByteReader + AsMut<[u8]> {}

impl<const N: usize> NoteByteWriter for NoteBytes<N> {}
