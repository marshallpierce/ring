use std::collections::HashSet;
use std::string::{String, ToString};
#[cfg(any(all(target_os="linux", test),
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
use std::path::Path;
use self::auxv::AuxvUnsignedLong;
#[cfg(any(all(target_os="linux", test),
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
use self::auxv::byteorder::NativeEndian;
#[cfg(any(test,
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
use self::auxv::{AT_HWCAP, AT_HWCAP2, AuxVals, GetauxvalError,
    GetauxvalProvider, NativeGetauxvalProvider};
use self::cpuinfo::CpuInfo;
#[cfg(any(all(target_os="linux", test),
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
use self::cpuinfo::parse_cpuinfo;

// Bits exposed in HWCAP and HWCAP2 auxv values
const ARM_HWCAP2_AES: AuxvUnsignedLong = 1 << 0;
const ARM_HWCAP2_PMULL: AuxvUnsignedLong = 1 << 1;
const ARM_HWCAP2_SHA1: AuxvUnsignedLong = 1 << 2;
const ARM_HWCAP2_SHA2: AuxvUnsignedLong = 1 << 3;

const ARM_HWCAP_NEON: AuxvUnsignedLong = 1 << 12;

// Constants used in GFp_armcap_P
// from include/openssl/arm_arch.h
#[cfg(any(test,
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
const ARMV7_NEON: u32 = 1 << 0;
// not a typo; there is no constant for 1 << 1
const ARMV8_AES: u32 = 1 << 2;
const ARMV8_SHA1: u32 = 1 << 3;
const ARMV8_SHA256: u32 = 1 << 4;
const ARMV8_PMULL: u32 = 1 << 5;

extern "C" {
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
        target_os="linux"))]
    #[allow(non_upper_case_globals)]
    pub static mut GFp_armcap_P: u32;
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os="linux"))]
pub fn arm_linux_set_cpu_features() {
    unsafe {
        GFp_armcap_P |= armcap_from_env();
    }
}

#[cfg(any(all(target_os="linux", test),
    all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
fn armcap_from_env() -> u32 {
    let cpu_info = match parse_cpuinfo() {
        Ok(c) => c,
        Err(_) => { return 0; }
    };

    let getauxval = NativeGetauxvalProvider{};

    let getauxval_works = match getauxval.getauxval(AT_HWCAP) {
        Ok(_) => true,
        Err(GetauxvalError::FunctionNotAvailable) => false,
        Err(_) => true
    };

    let procfs_auxv = if getauxval_works {
        // use empty auxv if getauxval is working
        AuxVals::new()
    } else {
        match auxv::search_procfs_auxv::<NativeEndian>
            (&Path::new("/proc/self/auxv"),
             &[AT_HWCAP, AT_HWCAP2]) {
            Ok(auxv) => auxv,
            Err(_) => AuxVals::new()
        }
    };

    armcap_from_features::<NativeGetauxvalProvider>(&cpu_info, &procfs_auxv,
                                                    getauxval)
}


/// returns a u32 with bits set for use in GFp_armcap_P
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os="linux")))]
fn armcap_from_features<G: GetauxvalProvider> (cpuinfo: &CpuInfo,
                                               procfs_auxv: &AuxVals,
                                               getauxval_provider: G)
                                               -> u32 {
    let mut hwcap: AuxvUnsignedLong = 0;

    // |getauxval| is not available on Android until API level 20. If it is
    // unavailable, read from /proc/self/auxv as a fallback. This is unreadable
    // on some versions of Android, so further fall back to /proc/cpuinfo.
    // See
    // https://android.googlesource.com/platform/ndk/+/882ac8f3392858991a0e1af33b4b7387ec856bd2
    // and b/13679666 (Google-internal) for details. */

    if let Ok(v) = getauxval_provider.getauxval(AT_HWCAP) {
        hwcap = v;
    } else if let Some(v) = procfs_auxv.get(&AT_HWCAP) {
        hwcap = *v;
    } else if let Some(v) = hwcap_from_cpuinfo(&cpuinfo) {
        hwcap = v;
    }

    // Clear NEON support if known broken
    if cpu_has_broken_neon(&cpuinfo) {
        hwcap &= !ARM_HWCAP_NEON;
    }

    // Matching OpenSSL, only report other features if NEON is present
    let mut armcap: u32 = 0;
    if hwcap & ARM_HWCAP_NEON > 0 {
        armcap |= ARMV7_NEON;

        // Some ARMv8 Android devices don't expose AT_HWCAP2. Fall back to
        // /proc/cpuinfo. See https://crbug.com/596156

        let mut hwcap2 = 0;
        if let Ok(v) = getauxval_provider.getauxval(AT_HWCAP2) {
            hwcap2 = v;
        } else if let Some(v) = procfs_auxv.get(&AT_HWCAP2) {
            hwcap2 = *v;
        } else if let Some(v) = hwcap2_from_cpuinfo(&cpuinfo) {
            hwcap2 = v;
        }

        armcap |= armcap_for_hwcap2(hwcap2);
    }

    return armcap;
}

fn armcap_for_hwcap2(hwcap2: AuxvUnsignedLong) -> u32 {
    let mut ret: u32 = 0;
    if hwcap2 & ARM_HWCAP2_AES > 0 {
        ret |= ARMV8_AES;
    }
    if hwcap2 & ARM_HWCAP2_PMULL > 0 {
        ret |= ARMV8_PMULL;
    }
    if hwcap2 & ARM_HWCAP2_SHA1 > 0 {
        ret |= ARMV8_SHA1;
    }
    if hwcap2 & ARM_HWCAP2_SHA2 > 0 {
        ret |= ARMV8_SHA256;
    }

    return ret;
}

fn hwcap_from_cpuinfo(cpuinfo: &CpuInfo) -> Option<AuxvUnsignedLong> {
    if let Some(v) = cpuinfo.get("CPU architecture") {
        if v == "8" {
            // This is a 32-bit ARM binary running on a 64-bit kernel. NEON is
            // always available on ARMv8. Linux omits required features, so
            // reading the "Features" line does not work. (For simplicity,
            // use strict equality. We assume everything running on future
            // ARM architectures will have a working |getauxval|.)
            return Some(ARM_HWCAP_NEON);
        }
    }

    if let Some(v) = cpuinfo.get("Features") {
        if parse_arm_cpuinfo_features(v).contains("neon") {
            return Some(ARM_HWCAP_NEON);
        }
    }

    return None;
}

fn hwcap2_from_cpuinfo(cpuinfo: &CpuInfo) -> Option<AuxvUnsignedLong> {
    if let Some(v) = cpuinfo.get("Features") {
        let mut ret: AuxvUnsignedLong = 0;
        let features = parse_arm_cpuinfo_features(v);

        if features.contains("aes") {
            ret |= ARM_HWCAP2_AES;
        }
        if features.contains("pmull") {
            ret |= ARM_HWCAP2_PMULL;
        }
        if features.contains("sha1") {
            ret |= ARM_HWCAP2_SHA1;
        }
        if features.contains("sha2") {
            ret |= ARM_HWCAP2_SHA2;
        }

        return Some(ret);
    } else {
        return None;
    }
}

fn cpu_has_broken_neon(cpuinfo: &CpuInfo) -> bool {
    return cpuinfo.get("CPU implementer").map_or(false, |s| s == "0x51") &&
        cpuinfo.get("CPU architecture").map_or( false, |s| s == "7") &&
        cpuinfo.get("CPU variant").map_or(false, |s| s == "0x1") &&
        cpuinfo.get("CPU part").map_or(false, |s| s == "0x04d") &&
        cpuinfo.get("CPU revision").map_or(false, |s| s == "0")
}

fn parse_arm_cpuinfo_features(features_val: &str) -> HashSet<String> {
    return features_val.trim_right_matches(' ')
        .split(' ')
        .map(|s| s.to_string())
        .collect();
}

mod auxv;
mod cpuinfo;

#[cfg(test)]
mod tests {
    extern crate byteorder;

    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{armcap_from_features, armcap_from_env, ARMV7_NEON,
        ARMV8_AES, ARMV8_PMULL, ARMV8_SHA1, ARMV8_SHA256, ARM_HWCAP2_AES,
        ARM_HWCAP2_PMULL, ARM_HWCAP2_SHA1, ARM_HWCAP2_SHA2,
        ARM_HWCAP_NEON};
    use super::cpuinfo::{parse_cpuinfo_reader, CpuInfo, CpuInfoError};
    use super::auxv::{AuxVals, AuxvUnsignedLong, GetauxvalError,
        GetauxvalProvider, AT_HWCAP, AT_HWCAP2};

    struct StubGetauxvalProvider {
        auxv: AuxVals
    }

    impl GetauxvalProvider for StubGetauxvalProvider {
        fn getauxval(&self, auxv_type: AuxvUnsignedLong)
                -> Result<AuxvUnsignedLong, GetauxvalError> {
            self.auxv.get(&auxv_type).map(|v| *v).ok_or(GetauxvalError::NotFound)
        }
    }

    #[test]
    fn armcap_from_env_doesnt_crash() {
        // can't really say anything useful about its result
        let _ = armcap_from_env();
    }

    #[test]
    fn armcap_bits_broken_neon_without_auxv_yields_zero_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo",
                            not_found_getauxv(),
                            &empty_procfs_auxv(),
                            0);
    }

    #[test]
    fn armcap_bits_broken_neon_with_neon_getauxv_yields_zero_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo",
                            hwcap_neon_getauxv(),
                            &empty_procfs_auxv(),
                            0);
    }

    #[test]
    fn armcap_bits_broken_neon_with_neon_procfs_yields_zero_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo",
                            not_found_getauxv(),
                            &hwcap_neon_procfs_auxv(),
                            0);
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_getauxv_yields_neon_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo",
                            hwcap_neon_getauxv(),
                            &empty_procfs_auxv(),
                            ARMV7_NEON);
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_procfs_auxv_yields_neon_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo",
                            not_found_getauxv(),
                            &hwcap_neon_procfs_auxv(),
                            ARMV7_NEON);
    }

    #[test]
    fn armcap_bits_ok_neon_without_auxv_yields_neon_only_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo",
                            not_found_getauxv(),
                            &empty_procfs_auxv(),
                            ARMV7_NEON);
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_without_auxv_yields_fully_populated_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo",
                            not_found_getauxv(),
                            &empty_procfs_auxv(),
                            ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                                | ARMV8_SHA256);
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_getauxv_hwcap_yields_fully_populated_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo",
                            hwcap_neon_getauxv(),
                            &empty_procfs_auxv(),
                            ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                                | ARMV8_SHA256);
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_procfs_auxv_hwcap_yields_fully_populated_armcap() {
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo",
                            not_found_getauxv(),
                            &hwcap_neon_procfs_auxv(),
                            ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                                | ARMV8_SHA256);
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_getauxv_hwcap_and_aes_getauxv_hwcap2_yields_only_neon_aes_armcap() {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(AT_HWCAP, ARM_HWCAP_NEON);
        let _ = auxv.insert(AT_HWCAP2, ARM_HWCAP2_AES);
        let getauxv = StubGetauxvalProvider {
            auxv: auxv
        };

        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo",
                            getauxv,
                            &empty_procfs_auxv(),
                            ARMV7_NEON | ARMV8_AES);
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_procfs_hwcap_and_pmull_procfs_hwcap2_yields_only_neon_aes_armcap() {
        let mut proc_auxv = AuxVals::new();
        let _ = proc_auxv.insert(AT_HWCAP,
                                 ARM_HWCAP_NEON);
        let _ = proc_auxv.insert(AT_HWCAP2,
                                 ARM_HWCAP2_PMULL);
        do_armcap_bits_test("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo",
                            not_found_getauxv(),
                            &proc_auxv,
                            ARMV7_NEON | ARMV8_PMULL);
    }

    #[test]
    fn armcap_for_hwcap2_zero_returns_zero() {
        assert_eq!(0, super::armcap_for_hwcap2(0));
    }

    #[test]
    fn armcap_for_hwcap2_all_hwcap2_returns_all_armcap() {
        assert_eq!(ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256,
            super::armcap_for_hwcap2(ARM_HWCAP2_AES
                                        | ARM_HWCAP2_PMULL
                                        | ARM_HWCAP2_SHA1
                                        | ARM_HWCAP2_SHA2));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_8_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "8".to_string());

        assert_eq!(Some(ARM_HWCAP_NEON),
            super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_with_feature_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());
        let _ = cpuinfo.insert("Features".to_string(),
                               "foo neon bar ".to_string());

        assert_eq!(Some(ARM_HWCAP_NEON),
            super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_without_feature_returns_none() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());

        assert_eq!(None, super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_missing_features_returns_none() {
        // x86 doesn't have "Features", it has "flags"
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo")).unwrap();

        assert_eq!(None, super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_sad_features_returns_zero() {
        // the broken cpu has weaksauce features
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        assert_eq!(Some(0), super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_fancy_features_returns_all() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("Features".to_string(),
                               "quux aes pmull sha1 sha2 foo ".to_string());

        assert_eq!(Some(ARM_HWCAP2_AES
                | ARM_HWCAP2_PMULL
                | ARM_HWCAP2_SHA1
                | ARM_HWCAP2_SHA2),
            super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_broken_neon_cpuinfo_detects_broken_arm() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        assert!(super::cpu_has_broken_neon(&cpuinfo));
    }

    #[test]
    fn arm_broken_neon_cpuinfo_ignores_x86() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo")).unwrap();

        assert!(!super::cpu_has_broken_neon(&cpuinfo));
    }

    #[test]
    fn parse_arm_features_handles_trailing_space() {
        let set = super::parse_arm_cpuinfo_features("foo bar baz ");
        assert_eq!(3, set.len());
        assert!(set.contains("baz"));
    }

    fn do_armcap_bits_test(path: &str, getauxval: StubGetauxvalProvider,
            proc_auxv: &AuxVals, expected_armcap: u32) {
        let cpuinfo = parse_cpuinfo_file(Path::new(path)).unwrap();

        assert_eq!(expected_armcap,
            armcap_from_features::<StubGetauxvalProvider>(&cpuinfo, proc_auxv,
                                                          getauxval));
    }

    fn parse_cpuinfo_file(path: &Path) -> Result<CpuInfo, CpuInfoError> {
        let mut buf = Vec::new();
        let mut f = File::open(path).unwrap();
        let _ = f.read_to_end(&mut buf).unwrap();

        let mut buffer = &buf[..];
        parse_cpuinfo_reader(&mut buffer)
    }

    fn empty_procfs_auxv() -> AuxVals {
        AuxVals::new()
    }

    fn hwcap_neon_procfs_auxv() ->  AuxVals {
        let mut proc_auxv = AuxVals::new();
        let _ = proc_auxv.insert(AT_HWCAP,
                                 ARM_HWCAP_NEON);

        proc_auxv
    }

    fn not_found_getauxv() -> StubGetauxvalProvider {
        StubGetauxvalProvider { auxv: AuxVals::new() }
    }

    fn hwcap_neon_getauxv() -> StubGetauxvalProvider {
        let mut auxv = AuxVals::new();
        let _ = auxv.insert(AT_HWCAP,
                            ARM_HWCAP_NEON);

        StubGetauxvalProvider {
            auxv: auxv
        }
    }
}
