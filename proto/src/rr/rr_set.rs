// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use std::iter::Chain;
use std::slice::Iter;
use std::vec;

use rr::{DNSClass, Name, RData, Record, RecordType};

#[cfg(feature = "dnssec")]
use rr::dnssec::SupportedAlgorithms;

/// Set of resource records associated to a name and type
#[derive(Clone, Debug, PartialEq)]
pub struct RecordSet {
    name: Name,
    record_type: RecordType,
    dns_class: DNSClass,
    ttl: u32,
    records: Vec<Record>,
    rrsigs: Vec<Record>,
    serial: u32, // serial number at which this record was modified
}

impl RecordSet {
    /// Creates a new Resource Record Set.
    ///
    /// # Arguments
    ///
    /// * `name` - The label for the `RecordSet`
    /// * `record_type` - `RecordType` of this `RecordSet`, all records in the `RecordSet` must be of the
    ///                   specified `RecordType`.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSec after updates.
    ///
    /// # Return value
    ///
    /// The newly created Resource Record Set
    /// TODO: make all cloned params pass by value
    pub fn new(name: &Name, record_type: RecordType, serial: u32) -> Self {
        RecordSet {
            name: name.clone(),
            record_type: record_type,
            dns_class: DNSClass::IN,
            ttl: 0,
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial: serial,
        }
    }

    /// Creates a new Resource Record Set.
    ///
    /// # Arguments
    ///
    /// * `name` - The label for the `RecordSet`
    /// * `record_type` - `RecordType` of this `RecordSet`, all records in the `RecordSet` must be of the
    ///                   specified `RecordType`.
    /// * `ttl` - time-to-live for the `RecordSet` in seconds.
    ///
    /// # Return value
    ///
    /// The newly created Resource Record Set
    /// TODO: make all cloned params pass by value
    pub fn with_ttl(name: Name, record_type: RecordType, ttl: u32) -> Self {
        RecordSet {
            name: name,
            record_type: record_type,
            dns_class: DNSClass::IN,
            ttl: ttl,
            records: Vec::new(),
            rrsigs: Vec::new(),
            serial: 0,
        }
    }

    /// Creates a new Resource Record Set from a Record
    ///
    /// # Arguments
    ///
    /// * `record` - initializes a record set with a single record
    ///
    /// # Return value
    ///
    /// The newly created Resource Record Set
    pub fn from(record: Record) -> Self {
        RecordSet {
            name: record.name().clone(),
            record_type: record.rr_type(),
            dns_class: record.dns_class(),
            ttl: record.ttl(),
            records: vec![record],
            rrsigs: vec![],
            serial: 0,
        }
    }

    /// # Return value
    ///
    /// Label of the Resource Record Set
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// # Return value
    ///
    /// `RecordType` of the Resource Record Set
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Sets the DNSClass to the specified value
    ///
    /// This will traverse every record and associate with it the specified dns_class
    pub fn set_dns_class(&mut self, dns_class: DNSClass) {
        self.dns_class = dns_class;
        for r in &mut self.records {
            r.set_dns_class(dns_class);
        }
    }

    /// Returns the `DNSClass` of the RecordSet
    pub fn dns_class(&self) -> DNSClass {
        self.dns_class
    }

    /// Sets the TTL, in seconds, to the specified value
    ///
    /// This will traverse every record and associate with it the specified ttl
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
        for r in &mut self.records {
            r.set_ttl(ttl);
        }
    }

    /// Returns the time-to-live for the record.
    ///
    /// # Return value
    ///
    /// TTL, time-to-live, of the Resource Record Set, this is the maximum length of time that an
    /// RecordSet should be cached.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Returns a Vec of all records in the set.
    ///
    /// # Arguments
    ///
    /// * `and_rrsigs` - if true, RRSIGs will be returned if they exist
    /// * `supported_algorithms` - the RRSIGs will be filtered by the set of supported_algorithms,
    ///                            and then only the maximal RRSIG algorithm will be returned.
    #[cfg(feature = "dnssec")]
    pub fn records(
        &self,
        and_rrsigs: bool,
        supported_algorithms: SupportedAlgorithms,
    ) -> Vec<&Record> {
        if and_rrsigs {
            self.records_with_rrsigs(supported_algorithms)
        } else {
            self.records_without_rrsigs()
        }
    }

    /// Returns a Vec of all records in the set, with RRSIGs, if present.
    ///
    /// # Arguments
    ///
    /// * `supported_algorithms` - the RRSIGs will be filtered by the set of supported_algorithms,
    ///                            and then only the maximal RRSIG algorithm will be returned.
    #[cfg(feature = "dnssec")]
    pub fn records_with_rrsigs(&self, supported_algorithms: SupportedAlgorithms) -> Vec<&Record> {
        use rr::dnssec::Algorithm;
        use rr::dnssec::rdata::DNSSECRData;

        // disable rfc 6975 when no supported_algorithms specified
        if supported_algorithms.is_empty() {
            return self.records.iter().chain(self.rrsigs.iter()).collect();
        }

        let rrsigs = self.rrsigs
            .iter()
            .filter(|record| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *record.rdata() {
                    supported_algorithms.has(rrsig.algorithm())
                } else {
                    false
                }
            })
            .max_by_key(|record| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref rrsig)) = *record.rdata() {
                    rrsig.algorithm()
                } else {
                    Algorithm::RSASHA1
                }
            });

        self.records.iter().chain(rrsigs).collect()
    }


    /// Returns a Vec of all records in the set, without any RRSIGs.
    pub fn records_without_rrsigs(&self) -> Vec<&Record> {
        self.records.iter().collect()
    }

    /// Returns an iterator over the records in the set
    pub fn iter<'s>(&'s self) -> Iter<'s, Record> {
        self.records.iter()
    }

    /// Returns true if there are no records in this set
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the serial number at which the record was updated.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Returns a slice of all the Records signatures in the RecordSet
    pub fn rrsigs(&self) -> &[Record] {
        &self.rrsigs
    }

    /// Inserts a Signature for the Record set
    ///
    /// Many can be associated with the RecordSet. Once added, the RecordSet should not be changed
    ///
    /// # Arguments
    ///
    /// * `rrsig` - A signature which covers the RecordSet.
    pub fn insert_rrsig(&mut self, rrsig: Record) {
        self.rrsigs.push(rrsig)
    }

    /// Useful for clearing all signatures when the RecordSet is updated, or keys are rotated.
    pub fn clear_rrsigs(&mut self) {
        self.rrsigs.clear()
    }

    fn updated(&mut self, serial: u32) {
        self.serial = serial;
        self.rrsigs.clear(); // on updates, the rrsigs are invalid
    }

    /// creates a new Record as part of this RecordSet, adding the associated RData
    pub fn new_record(&mut self, rdata: &RData) -> &Record {
        assert_eq!(self.record_type, rdata.to_record_type());

        let mut record = Record::with(self.name.clone(), self.record_type, self.ttl);
        record.set_rdata(rdata.clone()); // TODO: remove clone()? this is only needed for the record return
        self.insert(record, 0);

        self.records
            .iter()
            .find(|r| r.rdata() == rdata)
            .expect("insert failed? 172")
    }

    /// Inserts a new Resource Record into the Set.
    ///
    /// If the record is inserted, the ttl for the most recent record will be used for the ttl of
    /// the entire resource record set.
    ///
    /// This abides by the following restrictions in RFC 2136, April 1997:
    ///
    /// ```text
    /// 1.1.5. The following RR types cannot be appended to an RRset.  If the
    ///  following comparison rules are met, then an attempt to add the new RR
    ///  will result in the replacement of the previous RR:
    ///
    /// SOA    compare only NAME, CLASS and TYPE -- it is not possible to
    ///         have more than one SOA per zone, even if any of the data
    ///         fields differ.
    ///
    /// CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
    ///         to have more than one CNAME RR, even if their data fields
    ///         differ.
    /// ```
    ///
    /// # Arguments
    ///
    /// * `record` - `Record` asserts that the `name` and `record_type` match the `RecordSet`.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSec after updates. The serial will only be updated if the
    ///              record was added.
    ///
    /// # Return value
    ///
    /// True if the record was inserted.
    ///
    /// TODO: make a default add without serial number for basic usage
    pub fn insert(&mut self, record: Record, serial: u32) -> bool {
        assert_eq!(record.name(), &self.name);
        assert_eq!(record.rr_type(), self.record_type);

        // RFC 2136                       DNS Update                     April 1997
        //
        // 1.1.5. The following RR types cannot be appended to an RRset.  If the
        //  following comparison rules are met, then an attempt to add the new RR
        //  will result in the replacement of the previous RR:
        match record.rr_type() {
            // SOA    compare only NAME, CLASS and TYPE -- it is not possible to
            //         have more than one SOA per zone, even if any of the data
            //         fields differ.
            RecordType::SOA => {
                assert!(self.records.len() <= 1);

                if let Some(soa_record) = self.records.iter().next() {
                    match soa_record.rdata() {
                        &RData::SOA(ref existing_soa) => {
                            if let RData::SOA(ref new_soa) = *record.rdata() {
                                if new_soa.serial() <= existing_soa.serial() {
                                    info!(
                                        "update ignored serial out of data: {:?} <= {:?}",
                                        new_soa,
                                        existing_soa
                                    );
                                    return false;
                                }
                            } else {
                                // not panicking here, b/c this is a bad record from the client or something, ingnore
                                info!("wrong rdata for SOA update: {:?}", record.rdata());
                                return false;
                            }
                        }
                        rdata => panic!("wrong rdata: {:?}", rdata), // valid panic, never should happen
                    }
                }

                // if we got here, we're updating...
                self.records.clear();
            }
            // CNAME  compare only NAME, CLASS, and TYPE -- it is not possible
            //         to have more than one CNAME RR, even if their data fields
            //         differ.
            RecordType::CNAME => {
                assert!(self.records.len() <= 1);
                self.records.clear();
            }
            _ => (),
        }

        // collect any records to update based on rdata
        let to_replace: Vec<usize> = self.records
            .iter()
            .enumerate()
            .filter(|&(_, rr)| rr.rdata() == record.rdata())
            .map(|(i, _)| i)
            .collect::<Vec<usize>>();

        // if the Records are identical, ignore the update, update all that are not (ttl, etc.)
        let mut replaced = false;
        for i in to_replace {
            if self.records[i] == record {
                return false;
            }

            // TODO: this shouldn't really need a clone since there should only be one...
            self.records.push(record.clone());
            self.records.swap_remove(i);
            self.ttl = record.ttl();
            self.updated(serial);
            replaced = true;
        }

        if !replaced {
            self.ttl = record.ttl();
            self.updated(serial);
            self.records.push(record);
            true
        } else {
            replaced
        }
    }

    /// Removes the Resource Record if it exists.
    ///
    /// # Arguments
    ///
    /// * `record` - `Record` asserts that the `name` and `record_type` match the `RecordSet`. Removes
    ///              any `record` if the record data, `RData`, match.
    /// * `serial` - current serial number of the `SOA` record, this is to be used for `IXFR` and
    ///              signing for DNSSec after updates. The serial will only be updated if the
    ///              record was added.
    ///
    /// # Return value
    ///
    /// True if a record was removed.
    pub fn remove(&mut self, record: &Record, serial: u32) -> bool {
        assert_eq!(record.name(), &self.name);
        assert!(record.rr_type() == self.record_type || record.rr_type() == RecordType::ANY);

        match record.rr_type() {
            // never delete the last NS record
            RecordType::NS => if self.records.len() <= 1 {
                info!("ignoring delete of last NS record: {:?}", record);
                return false;
            },
            // never delete SOA
            RecordType::SOA => {
                info!("ignored delete of SOA");
                return false;
            }
            _ => (), // move on to the delete
        }

        // remove the records, first collect all the indexes, then remove the records
        let to_remove: Vec<usize> = self.records
            .iter()
            .enumerate()
            .filter(|&(_, rr)| rr.rdata() == record.rdata())
            .map(|(i, _)| i)
            .collect::<Vec<usize>>();

        let mut removed = false;
        for i in to_remove {
            self.records.remove(i);
            removed = true;
            self.updated(serial);
        }

        removed
    }
}

/// Types which implement this can be converted into a RecordSet
pub trait IntoRecordSet: Sized {
    /// Performs the conversion to a RecordSet
    fn into_record_set(self) -> RecordSet;
}

impl IntoRecordSet for RecordSet {
    fn into_record_set(self) -> Self {
        self
    }
}

impl IntoIterator for RecordSet {
    type Item = Record;
    type IntoIter = Chain<vec::IntoIter<Record>, vec::IntoIter<Record>>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter().chain(self.rrsigs.into_iter())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::net::Ipv4Addr;

    use rr::*;
    use rr::rdata::SOA;

    #[test]
    fn test_insert() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::A;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(record_type)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().len(), 1);
        assert!(rr_set.records_without_rrsigs().contains(&&insert));

        // dups ignored
        assert!(!rr_set.insert(insert.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().len(), 1);
        assert!(rr_set.records_without_rrsigs().contains(&&insert));

        // add one
        let insert1 = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(record_type)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 25)))
            .clone();
        assert!(rr_set.insert(insert1.clone(), 0));
        assert_eq!(rr_set.records_without_rrsigs().len(), 2);
        assert!(rr_set.records_without_rrsigs().contains(&&insert));
        assert!(rr_set.records_without_rrsigs().contains(&&insert1));
    }

    #[test]
    fn test_insert_soa() {
        let name = Name::from_str("example.com.").unwrap();
        let record_type = RecordType::SOA;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.org.").unwrap(),
                Name::from_str("noc.dns.icann.org.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone();
        let same_serial = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.net.").unwrap(),
                Name::from_str("noc.dns.icann.net.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone();
        let new_serial = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.net.").unwrap(),
                Name::from_str("noc.dns.icann.net.").unwrap(),
                2015082404,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.records_without_rrsigs().contains(&&insert));
        // same serial number
        assert!(!rr_set.insert(same_serial.clone(), 0));
        assert!(rr_set.records_without_rrsigs().contains(&&insert));
        assert!(!rr_set.records_without_rrsigs().contains(&&same_serial,));

        assert!(rr_set.insert(new_serial.clone(), 0));
        assert!(!rr_set.insert(same_serial.clone(), 0));
        assert!(!rr_set.insert(insert.clone(), 0));

        assert!(rr_set.records_without_rrsigs().contains(&&new_serial));
        assert!(!rr_set.records_without_rrsigs().contains(&&insert));
        assert!(!rr_set.records_without_rrsigs().contains(&&same_serial));
    }

    #[test]
    fn test_insert_cname() {
        let name = Name::from_str("web.example.com.").unwrap();
        let cname = Name::from_str("www.example.com.").unwrap();
        let new_cname = Name::from_str("w2.example.com.").unwrap();

        let record_type = RecordType::CNAME;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::CNAME)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::CNAME(cname.clone()))
            .clone();
        let new_record = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::CNAME)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::CNAME(new_cname.clone()))
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.records_without_rrsigs().contains(&&insert));

        // update the record
        assert!(rr_set.insert(new_record.clone(), 0));
        assert!(!rr_set.records_without_rrsigs().contains(&&insert));
        assert!(rr_set.records_without_rrsigs().contains(&&new_record));
    }

    #[test]
    fn test_remove() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::A;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(record_type)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone();
        let insert1 = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(record_type)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 25)))
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(rr_set.insert(insert1.clone(), 0));

        assert!(rr_set.remove(&insert, 0));
        assert!(!rr_set.remove(&insert, 0));
        assert!(rr_set.remove(&insert1, 0));
        assert!(!rr_set.remove(&insert1, 0));
    }

    #[test]
    fn test_remove_soa() {
        let name = Name::from_str("www.example.com.").unwrap();
        let record_type = RecordType::SOA;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let insert = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::SOA)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::SOA(SOA::new(
                Name::from_str("sns.dns.icann.org.").unwrap(),
                Name::from_str("noc.dns.icann.org.").unwrap(),
                2015082403,
                7200,
                3600,
                1209600,
                3600,
            )))
            .clone();

        assert!(rr_set.insert(insert.clone(), 0));
        assert!(!rr_set.remove(&insert, 0));
        assert!(rr_set.records_without_rrsigs().contains(&&insert));
    }

    #[test]
    fn test_remove_ns() {
        let name = Name::from_str("example.com.").unwrap();
        let record_type = RecordType::NS;
        let mut rr_set = RecordSet::new(&name, record_type, 0);

        let ns1 = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::from_str("a.iana-servers.net.").unwrap()))
            .clone();
        let ns2 = Record::new()
            .set_name(name.clone())
            .set_ttl(86400)
            .set_rr_type(RecordType::NS)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::NS(Name::from_str("b.iana-servers.net.").unwrap()))
            .clone();

        assert!(rr_set.insert(ns1.clone(), 0));
        assert!(rr_set.insert(ns2.clone(), 0));

        // ok to remove one, but not two...
        assert!(rr_set.remove(&ns1, 0));
        assert!(!rr_set.remove(&ns2, 0));

        // check that we can swap which ones are removed
        assert!(rr_set.insert(ns1.clone(), 0));

        assert!(rr_set.remove(&ns2, 0));
        assert!(!rr_set.remove(&ns1, 0));
    }

    #[test]
    #[cfg(feature = "dnssec")] // This tests RFC 6975, a DNSSEC-specific feature.
    fn test_get_filter() {
        use rr::dnssec::rdata::SIG;
        use rr::dnssec::{Algorithm, SupportedAlgorithms};
        use rr::dnssec::rdata::{DNSSECRData, DNSSECRecordType};

        let name = Name::root();
        let rsasha256 = SIG::new(
            RecordType::A,
            Algorithm::RSASHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp256 = SIG::new(
            RecordType::A,
            Algorithm::ECDSAP256SHA256,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ecp384 = SIG::new(
            RecordType::A,
            Algorithm::ECDSAP384SHA384,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );
        let ed25519 = SIG::new(
            RecordType::A,
            Algorithm::ED25519,
            0,
            0,
            0,
            0,
            0,
            Name::root(),
            vec![],
        );

        let rrsig_rsa = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::DNSSEC(DNSSECRecordType::RRSIG))
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::DNSSEC(DNSSECRData::SIG(rsasha256)))
            .clone();
        let rrsig_ecp256 = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::DNSSEC(DNSSECRecordType::RRSIG))
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::DNSSEC(DNSSECRData::SIG(ecp256)))
            .clone();
        let rrsig_ecp384 = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::DNSSEC(DNSSECRecordType::RRSIG))
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::DNSSEC(DNSSECRData::SIG(ecp384)))
            .clone();
        let rrsig_ed25519 = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::DNSSEC(DNSSECRecordType::RRSIG))
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::DNSSEC(DNSSECRData::SIG(ed25519)))
            .clone();

        let a = Record::new()
            .set_name(name.clone())
            .set_ttl(3600)
            .set_rr_type(RecordType::A)
            .set_dns_class(DNSClass::IN)
            .set_rdata(RData::A(Ipv4Addr::new(93, 184, 216, 24)))
            .clone();

        let mut rrset = a.into_record_set();
        rrset.insert_rrsig(rrsig_rsa);
        rrset.insert_rrsig(rrsig_ecp256);
        rrset.insert_rrsig(rrsig_ecp384);
        rrset.insert_rrsig(rrsig_ed25519);

        assert!(
            rrset
                .records_with_rrsigs(SupportedAlgorithms::all(),)
                .iter()
                .any(|r| {
                    if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *r.rdata() {
                        sig.algorithm() == Algorithm::ED25519
                    } else {
                        false
                    }
                },)
        );

        let mut supported_algorithms = SupportedAlgorithms::new();
        supported_algorithms.set(Algorithm::ECDSAP384SHA384);
        assert!(rrset.records_with_rrsigs(supported_algorithms).iter().any(
            |r| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *r.rdata() {
                    sig.algorithm() == Algorithm::ECDSAP384SHA384
                } else {
                    false
                }
            }
        ));

        let mut supported_algorithms = SupportedAlgorithms::new();
        supported_algorithms.set(Algorithm::ED25519);
        assert!(rrset.records_with_rrsigs(supported_algorithms).iter().any(
            |r| {
                if let RData::DNSSEC(DNSSECRData::SIG(ref sig)) = *r.rdata() {
                    sig.algorithm() == Algorithm::ED25519
                } else {
                    false
                }
            }
        ));
    }
}
