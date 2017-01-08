pub extern crate byteorder;

use std;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;
use std::vec::Vec;

use self::byteorder::{ByteOrder, ReadBytesExt};

#[cfg(any(all(target_pointer_width = "32", test),
    all(target_pointer_width = "32", target_os = "linux")))]
pub type AuxvUnsignedLong = u32;
#[cfg(any(all(target_pointer_width = "64", test),
    all(target_pointer_width = "64", target_os = "linux")))]
pub type AuxvUnsignedLong = u64;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, sets success to false and returns 0.
    #[cfg(target_os="linux")]
    pub fn getauxval_wrapper(auxv_type: AuxvUnsignedLong,
                             success: *mut AuxvUnsignedLong) -> i32;
}

#[derive(Debug, PartialEq)]
pub enum GetauxvalError {
    #[cfg(target_os="linux")]
    FunctionNotAvailable,
    NotFound,
    #[cfg(target_os="linux")]
    UnknownError
}

pub trait GetauxvalProvider {
    fn getauxval(&self, auxv_type: AuxvUnsignedLong)
        -> Result<AuxvUnsignedLong, GetauxvalError>;
}

#[cfg(target_os="linux")]
pub struct NativeGetauxvalProvider {}

#[cfg(target_os="linux")]
impl GetauxvalProvider for NativeGetauxvalProvider {
    /// Returns Some if the native invocation succeeds and the requested type was
    /// found, otherwise None.
    fn getauxval(&self, auxv_type: AuxvUnsignedLong)
            -> Result<AuxvUnsignedLong, GetauxvalError> {

        let mut result = 0;
        unsafe {
            return match getauxval_wrapper(auxv_type, &mut result) {
                1 => Ok(result),
                0 => Err(GetauxvalError::NotFound),
                -1 => Err(GetauxvalError::FunctionNotAvailable),
                _ => Err(GetauxvalError::UnknownError)
            }
        }
    }
}

// from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP
// even on platforms where unsigned long is 64 bits.
pub const AT_HWCAP: AuxvUnsignedLong = 16;
// currently only used by powerpc and arm64 AFAICT
pub const AT_HWCAP2: AuxvUnsignedLong = 26;

pub type AuxVals = HashMap<AuxvUnsignedLong, AuxvUnsignedLong>;

#[derive(Debug, PartialEq)]
pub enum AuxValError {
    IoError,
    InvalidFormat
}

/// Read an entry from the procfs auxv file.
///
/// input: pairs of unsigned longs, as in /proc/self/auxv. The first of each
/// pair is the 'type' and the second is the 'value'.
///
/// aux_types: the types to look for
/// returns a map of types to values, only including entries for types that were
/// requested that also had values in the aux vector
pub fn search_procfs_auxv<B: ByteOrder>(path: &Path,
                                        aux_types: &[AuxvUnsignedLong])
                                        -> Result<AuxVals, AuxValError> {
    let mut input = File::open(path)
        .map_err(|_| AuxValError::IoError)
        .map(|f| BufReader::new(f))?;

    let ulong_size = std::mem::size_of::<AuxvUnsignedLong>();
    let mut buf: Vec<u8> = Vec::with_capacity(2 * ulong_size);
    let mut result = HashMap::<AuxvUnsignedLong, AuxvUnsignedLong>::new();

    loop {
        buf.clear();
        // fill vec so we can slice into it
        for _ in 0 .. 2 * ulong_size {
            buf.push(0);
        }

        let mut read_bytes: usize = 0;
        while read_bytes < 2 * ulong_size {
            // read exactly buf's len of bytes.
            match input.read(&mut buf[read_bytes..]) {
                Ok(n) => {
                    if n == 0 {
                        // should not hit EOF before AT_NULL
                        return Err(AuxValError::InvalidFormat)
                    }

                    read_bytes += n;
                }
                Err(_) => return Err(AuxValError::IoError)
            }
        }

        let mut reader = &buf[..];
        let found_aux_type = read_long::<B>(&mut reader)
            .map_err(|_| AuxValError::InvalidFormat)?;
        let aux_val = read_long::<B>(&mut reader)
            .map_err(|_| AuxValError::InvalidFormat)?;

        if aux_types.contains(&found_aux_type) {
            let _ = result.insert(found_aux_type, aux_val);
        }

        // AT_NULL (0) signals the end of auxv
        if found_aux_type == 0 {
            return Ok(result);
        }
    }
}

#[cfg(any(all(target_pointer_width = "32", test),
all(target_pointer_width = "32", target_os = "linux")))]
fn read_long<B: ByteOrder> (reader: &mut Read) -> std::io::Result<AuxvUnsignedLong>{
    reader.read_u32::<B>()
}

#[cfg(any(all(target_pointer_width = "64", test),
all(target_pointer_width = "64", target_os = "linux")))]
fn read_long<B: ByteOrder> (reader: &mut Read) -> std::io::Result<AuxvUnsignedLong>{
    reader.read_u64::<B>()
}

#[cfg(test)]
mod tests {
    extern crate byteorder;

    use std::path::Path;
    #[cfg(target_pointer_width = "64")]
    use super::AuxValError;
    use super::{search_procfs_auxv, AuxvUnsignedLong, AT_HWCAP, AT_HWCAP2};
    #[cfg(target_os="linux")]
    use super::{GetauxvalError, GetauxvalProvider,
        NativeGetauxvalProvider};

    use self::byteorder::LittleEndian;

    // uid of program that read /proc/self/auxv
    const AT_UID: AuxvUnsignedLong = 11;

    // x86 hwcap bits from [linux]/arch/x86/include/asm/cpufeature.h
    const X86_FPU: u32 = 0 * 32 + 0;
    const X86_ACPI: u32 = 0 * 32 + 22;

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_finds_hwcap() {
        let native_getauxval = NativeGetauxvalProvider{};
        let result = native_getauxval.getauxval(AT_HWCAP);
        // there should be SOMETHING in the value
        assert!(result.unwrap() > 0);
    }

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_doesnt_find_bogus_type() {
        let native_getauxval = NativeGetauxvalProvider{};

        // AT_NULL aka 0 is effectively the EOF for auxv, so it's never a valid type
        assert_eq!(GetauxvalError::NotFound, native_getauxval.getauxval(0).unwrap_err());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_virtualbox_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x64-4850HQ.auxv");
        let vals = search_procfs_auxv::<LittleEndian>(path, &[AT_HWCAP, AT_HWCAP2, AT_UID])
            .unwrap();
        let hwcap = vals.get(&AT_HWCAP).unwrap();
        assert_eq!(&395049983_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        // virtualized, no acpi via msr I guess
        assert_eq!(0, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn test_parse_auxv_virtualbox_linux_32bit() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x86-4850HQ.auxv");
        let vals = search_procfs_auxv::<LittleEndian>(path, &[AT_HWCAP, AT_HWCAP2, AT_UID])
            .unwrap();
        let hwcap = vals.get(&AT_HWCAP).unwrap();
        assert_eq!(&126614527_u32, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        // virtualized, no acpi via msr I guess
        assert_eq!(0, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&AT_HWCAP2));

        // this auxv was while running as root (unlike other auxv files)
        assert_eq!(&0_u32, vals.get(&AT_UID).unwrap());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_virtualbox_linux_32bit_in_64bit_mode_invalidformat() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x86-4850HQ.auxv");
        let vals = search_procfs_auxv::<LittleEndian>(path, &[AT_HWCAP, AT_HWCAP2, AT_UID]);

        assert_eq!(Err(AuxValError::InvalidFormat), vals);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_real_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.auxv");
        let vals = search_procfs_auxv::<LittleEndian>(path, &[AT_HWCAP, AT_HWCAP2, AT_UID])
            .unwrap();
        let hwcap = vals.get(&AT_HWCAP).unwrap();

        assert_eq!(&3219913727_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        assert_eq!(1 << X86_ACPI, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_real_linux_half_of_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-value-in-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<LittleEndian>(path, &[555555555]).unwrap_err());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_real_linux_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<LittleEndian>(path, &[555555555]).unwrap_err());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_auxv_real_linux_truncated_entry_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-truncated-entry.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<LittleEndian>(path, &[555555555]).unwrap_err());
    }
}
